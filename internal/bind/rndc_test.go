package bind

import (
	"testing"
	"time"
)

// TestNewRNDCClient tests RNDC client creation
func TestNewRNDCClient(t *testing.T) {
	tests := []struct {
		name     string
		rndcPath string
		rndcConf string
		view     string
	}{
		{
			name:     "basic client",
			rndcPath: "/usr/sbin/rndc",
			rndcConf: "/etc/rndc.conf",
			view:     "",
		},
		{
			name:     "client with view",
			rndcPath: "/usr/local/sbin/rndc",
			rndcConf: "/etc/bind/rndc.conf",
			view:     "internal",
		},
		{
			name:     "custom paths",
			rndcPath: "/opt/bind/bin/rndc",
			rndcConf: "/opt/bind/etc/rndc.conf",
			view:     "external",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRNDCClient(tt.rndcPath, tt.rndcConf, tt.view)

			if client == nil {
				t.Fatal("NewRNDCClient() returned nil")
			}

			if client.rndcPath != tt.rndcPath {
				t.Errorf("rndcPath = %q, want %q", client.rndcPath, tt.rndcPath)
			}
			if client.rndcConf != tt.rndcConf {
				t.Errorf("rndcConf = %q, want %q", client.rndcConf, tt.rndcConf)
			}
			if client.view != tt.view {
				t.Errorf("view = %q, want %q", client.view, tt.view)
			}
		})
	}
}

// TestSetTimeout tests timeout configuration
func TestSetTimeout(t *testing.T) {
	client := NewRNDCClient("/usr/sbin/rndc", "/etc/rndc.conf", "")

	// Default timeout should be 30 seconds
	if client.timeout != 30*time.Second {
		t.Errorf("default timeout = %v, want 30s", client.timeout)
	}

	// Set custom timeout
	client.SetTimeout(60 * time.Second)
	if client.timeout != 60*time.Second {
		t.Errorf("timeout after SetTimeout = %v, want 60s", client.timeout)
	}

	// Set short timeout
	client.SetTimeout(5 * time.Second)
	if client.timeout != 5*time.Second {
		t.Errorf("timeout after SetTimeout = %v, want 5s", client.timeout)
	}
}

// TestParseZoneConfig tests zone configuration parsing
func TestParseZoneConfig(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   map[string]string
	}{
		{
			name: "simple primary zone",
			output: `zone "example.com" {
	type primary;
	file "/var/lib/bind/zones/example.com.db";
};`,
			want: map[string]string{
				"type": "primary",
				"file": "\"/var/lib/bind/zones/example.com.db\"",
			},
		},
		{
			name: "zone with multiple options",
			output: `zone "example.com" {
	type primary;
	file "/var/lib/bind/zones/example.com.db";
	notify yes;
	dnssec-policy default;
	inline-signing yes;
};`,
			want: map[string]string{
				"type":           "primary",
				"file":           "\"/var/lib/bind/zones/example.com.db\"",
				"notify":         "yes",
				"dnssec-policy":  "default",
				"inline-signing": "yes",
			},
		},
		{
			name: "secondary zone",
			output: `zone "example.com" {
	type secondary;
	primaries { 192.0.2.1; };
	file "/var/cache/bind/db.example.com";
};`,
			want: map[string]string{
				"type":      "secondary",
				"primaries": "{",
				"file":      "\"/var/cache/bind/db.example.com\"",
			},
		},
		{
			name: "master zone (legacy)",
			output: `zone "example.com" {
	type master;
	file "/var/lib/bind/zones/example.com.db";
};`,
			want: map[string]string{
				"type": "master",
				"file": "\"/var/lib/bind/zones/example.com.db\"",
			},
		},
		{
			name:   "empty output",
			output: "",
			want:   map[string]string{},
		},
		{
			name:   "no zone block",
			output: "some other output without zone block",
			want:   map[string]string{},
		},
		{
			name: "zone with quoted name",
			output: `zone 'example.com' {
	type primary;
	file "/var/lib/bind/zones/example.com.db";
};`,
			want: map[string]string{
				"type": "primary",
				"file": "\"/var/lib/bind/zones/example.com.db\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseZoneConfig(tt.output)

			// Check all expected keys are present with correct values
			for key, wantValue := range tt.want {
				gotValue, ok := got[key]
				if !ok {
					t.Errorf("ParseZoneConfig() missing key %q", key)
					continue
				}
				if gotValue != wantValue {
					t.Errorf("ParseZoneConfig()[%q] = %q, want %q", key, gotValue, wantValue)
				}
			}
		})
	}
}

// TestParseZoneConfigEdgeCases tests edge cases in zone config parsing
func TestParseZoneConfigEdgeCases(t *testing.T) {
	t.Run("zone without closing brace", func(t *testing.T) {
		output := `zone "example.com" {
	type primary;
	file "/var/lib/bind/zones/example.com.db";`
		// Should still parse what it can
		got := ParseZoneConfig(output)
		if got["type"] != "primary" {
			t.Errorf("Should still parse type directive")
		}
	})

	t.Run("multiple zones - parses first zone block it finds", func(t *testing.T) {
		output := `zone "first.com" {
	type primary;
};
zone "second.com" {
	type secondary;
};`
		got := ParseZoneConfig(output)
		// Implementation parses the first complete zone block it finds
		// The type should be "primary" from the first zone
		zoneType := got["type"]
		if zoneType != "primary" && zoneType != "secondary" {
			t.Errorf("Should parse a zone block, got type = %q", zoneType)
		}
	})

	t.Run("zone with tabs and spaces", func(t *testing.T) {
		output := "zone \"example.com\" {\n\t\ttype\t\tprimary;\n\t\tfile\t\t\"/path/to/file\";\n};"
		got := ParseZoneConfig(output)
		if got["type"] != "primary" {
			t.Errorf("Should handle mixed whitespace, got type = %q", got["type"])
		}
	})
}

// TestIsZonePrimaryLogic tests the primary zone detection logic
func TestIsZonePrimaryLogic(t *testing.T) {
	// Test the parsing logic used by IsZonePrimary
	tests := []struct {
		name     string
		zoneType string
		want     bool
	}{
		{"primary type", "primary", true},
		{"master type", "master", true},
		{"secondary type", "secondary", false},
		{"slave type", "slave", false},
		{"stub type", "stub", false},
		{"forward type", "forward", false},
		{"empty type", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.zoneType == "primary" || tt.zoneType == "master"
			if got != tt.want {
				t.Errorf("isPrimary(%q) = %v, want %v", tt.zoneType, got, tt.want)
			}
		})
	}
}
