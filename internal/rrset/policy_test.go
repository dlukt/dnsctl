package rrset

import (
	"testing"

	"github.com/dlukt/dnsctl/internal/config"
)

// TestValidatePolicy tests policy enforcement rules
func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name       string
		disallowApexCNAME bool
		disallowNSUpdates bool
		zone       string
		owner      string
		rrType     string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "CNAME at apex - disallowed",
			disallowApexCNAME: true,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "CNAME",
			wantErr:    true,
			errMsg:     "CNAME at zone apex",
		},
		{
			name:       "CNAME at apex - allowed",
			disallowApexCNAME: false,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "CNAME",
			wantErr:    false,
		},
		{
			name:       "CNAME at subdomain - allowed",
			disallowApexCNAME: true,
			zone:       "example.com.",
			owner:      "www.example.com.",
			rrType:     "CNAME",
			wantErr:    false,
		},
		{
			name:       "NS update - disallowed",
			disallowNSUpdates: true,
			zone:       "example.com.",
			owner:      "www.example.com.",
			rrType:     "NS",
			wantErr:    true,
			errMsg:     "NS record updates",
		},
		{
			name:       "NS update - allowed",
			disallowNSUpdates: false,
			zone:       "example.com.",
			owner:      "www.example.com.",
			rrType:     "NS",
			wantErr:    false,
		},
		{
			name:       "A record at apex - always allowed",
			disallowApexCNAME: true,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "A",
			wantErr:    false,
		},
		{
			name:       "AAAA record at apex - always allowed",
			disallowApexCNAME: true,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "AAAA",
			wantErr:    false,
		},
		{
			name:       "MX record at apex - always allowed",
			disallowApexCNAME: true,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "MX",
			wantErr:    false,
		},
		{
			name:       "TXT record at apex - always allowed",
			disallowApexCNAME: true,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "TXT",
			wantErr:    false,
		},
		{
			name:       "NS record at apex - also disallowed",
			disallowNSUpdates: true,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "NS",
			wantErr:    true, // DisallowNSUpdates applies to all NS updates
			errMsg:     "NS record updates",
		},
		{
			name:       "SRV record at subdomain - always allowed",
			disallowApexCNAME: true,
			disallowNSUpdates: true,
			zone:       "example.com.",
			owner:      "_ldap._tcp.example.com.",
			rrType:     "SRV",
			wantErr:    false,
		},
		{
			name:       "CAA record at apex - always allowed",
			disallowApexCNAME: true,
			zone:       "example.com.",
			owner:      "example.com.",
			rrType:     "CAA",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Policy: config.PolicyConfig{
					AllowedRRtypes:    []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS"},
					DisallowApexCNAME: tt.disallowApexCNAME,
					DisallowNSUpdates: tt.disallowNSUpdates,
					MinTTL:            60,
					MaxTTL:            86400,
				},
			}
			v := NewValidator(cfg)

			err := v.ValidatePolicy(tt.zone, tt.owner, tt.rrType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePolicy(%q, %q, %q) error = %v, wantErr %v",
					tt.zone, tt.owner, tt.rrType, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidatePolicy error = %v, expected to contain %q", err, tt.errMsg)
				}
			}
		})
	}
}

// TestValidatePolicyEdgeCases tests edge cases for policy validation
func TestValidatePolicyEdgeCases(t *testing.T) {
	cfg := &config.Config{
		Policy: config.PolicyConfig{
			AllowedRRtypes:    []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS"},
			DisallowApexCNAME: true,
			DisallowNSUpdates: true,
			MinTTL:            60,
			MaxTTL:            86400,
		},
	}
	v := NewValidator(cfg)

	t.Run("case insensitive RR type", func(t *testing.T) {
		err := v.ValidatePolicy("example.com.", "example.com.", "cname")
		if err == nil {
			t.Error("expected error for CNAME at apex (case insensitive)")
		}
	})

	t.Run("case insensitive zone/owner comparison", func(t *testing.T) {
		err := v.ValidatePolicy("EXAMPLE.COM.", "example.com.", "CNAME")
		if err == nil {
			t.Error("expected error for CNAME at apex (case insensitive)")
		}
	})

	t.Run("empty owner is not apex (no special handling)", func(t *testing.T) {
		err := v.ValidatePolicy("example.com.", "", "CNAME")
		if err != nil {
			t.Errorf("unexpected error for empty owner: %v", err)
		}
	})
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsMiddle(s, substr)))
}

// containsMiddle is a helper for contains
func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
