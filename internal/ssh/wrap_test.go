package ssh

import (
	"testing"
)

// TestParseCommand tests command string parsing
func TestParseCommand(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantParts []string
		wantErr   bool
	}{
		{
			name:      "simple command",
			input:     "zone create example.com",
			wantParts: []string{"zone", "create", "example.com"},
			wantErr:   false,
		},
		{
			name:      "single word",
			input:     "doctor",
			wantParts: []string{"doctor"},
			wantErr:   false,
		},
		{
			name:      "command with flags",
			input:     "rrset upsert --ttl 3600 example.com www A 192.0.2.1",
			wantParts: []string{"rrset", "upsert", "--ttl", "3600", "example.com", "www", "A", "192.0.2.1"},
			wantErr:   false,
		},
		{
			name:      "empty command",
			input:     "",
			wantParts: nil,
			wantErr:   true,
		},
		{
			name:      "whitespace only",
			input:     "   ",
			wantParts: []string{},
			wantErr:   false, // strings.Fields returns empty slice for whitespace-only
		},
		{
			name:      "multiple spaces between args",
			input:     "zone    create    example.com",
			wantParts: []string{"zone", "create", "example.com"},
			wantErr:   false,
		},
		{
			name:      "leading and trailing spaces",
			input:     "   zone create example.com   ",
			wantParts: []string{"zone", "create", "example.com"},
			wantErr:   false,
		},
		{
			name:      "tabs as separators",
			input:     "zone\tcreate\texample.com",
			wantParts: []string{"zone", "create", "example.com"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCommand(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCommand(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.wantParts) {
					t.Errorf("ParseCommand(%q) = %v (len %d), want %v (len %d)",
						tt.input, got, len(got), tt.wantParts, len(tt.wantParts))
					return
				}
				for i := range got {
					if got[i] != tt.wantParts[i] {
						t.Errorf("ParseCommand(%q)[%d] = %q, want %q",
							tt.input, i, got[i], tt.wantParts[i])
					}
				}
			}
		})
	}
}

// TestValidateCommand tests command validation against allowlist
func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name    string
		parts   []string
		wantErr bool
		errMsg  string
	}{
		// Allowed commands
		{
			name:    "doctor command",
			parts:   []string{"doctor"},
			wantErr: false,
		},
		{
			name:    "version command",
			parts:   []string{"version"},
			wantErr: false,
		},
		{
			name:    "zone command",
			parts:   []string{"zone", "create", "example.com"},
			wantErr: false,
		},
		{
			name:    "rrset command",
			parts:   []string{"rrset", "upsert", "example.com", "www", "A", "192.0.2.1"},
			wantErr: false,
		},
		{
			name:    "acme command",
			parts:   []string{"acme", "present", "example.com", "www", "token123"},
			wantErr: false,
		},
		// Disallowed commands
		{
			name:    "unknown command",
			parts:   []string{"unknown"},
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name:    "shell command injection attempt",
			parts:   []string{"bash", "-c", "rm -rf /"},
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name:    "empty command parts",
			parts:   []string{},
			wantErr: true,
			errMsg:  "empty",
		},
		{
			name:    "config command (not allowed)",
			parts:   []string{"config", "show"},
			wantErr: true,
			errMsg:  "not allowed",
		},
		{
			name:    "exec attempt",
			parts:   []string{"exec", "malicious"},
			wantErr: true,
			errMsg:  "not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCommand(tt.parts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCommand(%v) error = %v, wantErr %v", tt.parts, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateCommand(%v) error = %v, want error containing %q",
						tt.parts, err, tt.errMsg)
				}
			}
		})
	}
}

// TestAllowedSubcommands tests that the allowlist is correctly defined
func TestAllowedSubcommands(t *testing.T) {
	expectedAllowed := []string{"doctor", "version", "zone", "rrset", "acme"}

	for _, cmd := range expectedAllowed {
		t.Run(cmd, func(t *testing.T) {
			if !allowedSubcommands[cmd] {
				t.Errorf("Expected %q to be allowed", cmd)
			}
		})
	}

	expectedDisallowed := []string{"exec", "shell", "bash", "sh", "config", "init"}

	for _, cmd := range expectedDisallowed {
		t.Run("disallowed_"+cmd, func(t *testing.T) {
			if allowedSubcommands[cmd] {
				t.Errorf("Expected %q to be disallowed", cmd)
			}
		})
	}
}

// TestAllowedFlags tests that flags are correctly validated per subcommand
func TestAllowedFlags(t *testing.T) {
	tests := []struct {
		subcommand string
		flag       string
		allowed    bool
	}{
		// Zone subcommand flags
		{"zone", "create", true},
		{"zone", "delete", true},
		{"zone", "status", true},
		{"zone", "list", true},
		{"zone", "limit", true},
		{"zone", "exec", false},

		// RRset subcommand flags
		{"rrset", "upsert", true},
		{"rrset", "delete", true},
		{"rrset", "get", true},
		{"rrset", "ttl", true},
		{"rrset", "exec", false},

		// ACME subcommand flags
		{"acme", "present", true},
		{"acme", "cleanup", true},
		{"acme", "ttl", true},
		{"acme", "exec", false},
	}

	for _, tt := range tests {
		t.Run(tt.subcommand+"_"+tt.flag, func(t *testing.T) {
			flags := allowedFlags[tt.subcommand]
			if flags == nil && tt.allowed {
				t.Errorf("No flags defined for subcommand %q", tt.subcommand)
				return
			}
			if flags != nil && flags[tt.flag] != tt.allowed {
				t.Errorf("allowedFlags[%q][%q] = %v, want %v",
					tt.subcommand, tt.flag, flags[tt.flag], tt.allowed)
			}
		})
	}
}

// TestNewWrapHandler tests wrap handler creation
func TestNewWrapHandler(t *testing.T) {
	handler := NewWrapHandler(nil)
	if handler == nil {
		t.Error("NewWrapHandler() returned nil")
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
