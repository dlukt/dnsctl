package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultConfig tests that DefaultConfig returns sensible defaults
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	// Test BIND defaults
	if cfg.Bind.RNDCPath != "/usr/sbin/rndc" {
		t.Errorf("DefaultConfig().Bind.RNDCPath = %q, want /usr/sbin/rndc", cfg.Bind.RNDCPath)
	}
	if cfg.Bind.DNSAddr != "127.0.0.1" {
		t.Errorf("DefaultConfig().Bind.DNSAddr = %q, want 127.0.0.1", cfg.Bind.DNSAddr)
	}
	if cfg.Bind.DNSPort != 53 {
		t.Errorf("DefaultConfig().Bind.DNSPort = %d, want 53", cfg.Bind.DNSPort)
	}

	// Test Policy defaults (actual defaults from implementation)
	if cfg.Policy.MinTTL != 30 {
		t.Errorf("DefaultConfig().Policy.MinTTL = %d, want 30", cfg.Policy.MinTTL)
	}
	if cfg.Policy.MaxTTL != 86400 {
		t.Errorf("DefaultConfig().Policy.MaxTTL = %d, want 86400", cfg.Policy.MaxTTL)
	}

	// Test that allowed RR types are set
	if len(cfg.Policy.AllowedRRtypes) == 0 {
		t.Error("DefaultConfig().Policy.AllowedRRtypes is empty")
	}

	// Test catalog defaults
	if cfg.Catalog.SchemaVersion != 2 {
		t.Errorf("DefaultConfig().Catalog.SchemaVersion = %d, want 2", cfg.Catalog.SchemaVersion)
	}
	if cfg.Catalog.LabelAlgorithm != "sha1-wire" {
		t.Errorf("DefaultConfig().Catalog.LabelAlgorithm = %q, want sha1-wire", cfg.Catalog.LabelAlgorithm)
	}
}

// TestLoadConfig tests loading configuration from a YAML file
func TestLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid complete config file", func(t *testing.T) {
		// Create TSIG secret file
		tsigSecretPath := filepath.Join(tmpDir, "tsig.key")
		if err := os.WriteFile(tsigSecretPath, []byte("supersecretkey"), 0600); err != nil {
			t.Fatalf("Failed to write TSIG secret: %v", err)
		}

		configPath := filepath.Join(tmpDir, "valid.yaml")
		configContent := `
bind:
  rndc_path: /usr/local/sbin/rndc
  rndc_conf: /etc/rndc.conf
  dns_addr: 192.168.1.1
  dns_port: 5353
catalog:
  zone: catalog.example.com.
  schema_version: 2
  label_algorithm: sha1-wire
zones:
  dir: /var/lib/bind
  file_extension: db
  update_mode: allow-update
tsig:
  name: dnsctl-key.
  algorithm: hmac-sha256
  secret_file: ` + tsigSecretPath + `
policy:
  min_ttl: 30
  max_ttl: 172800
  allowed_rrtypes:
    - A
    - AAAA
    - TXT
locking:
  dir: /var/lock/dnsctl
`
		if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		cfg, err := Load(configPath)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}

		if cfg.Bind.RNDCPath != "/usr/local/sbin/rndc" {
			t.Errorf("Load().Bind.RNDCPath = %q, want /usr/local/sbin/rndc", cfg.Bind.RNDCPath)
		}
		if cfg.Bind.DNSAddr != "192.168.1.1" {
			t.Errorf("Load().Bind.DNSAddr = %q, want 192.168.1.1", cfg.Bind.DNSAddr)
		}
		if cfg.Bind.DNSPort != 5353 {
			t.Errorf("Load().Bind.DNSPort = %d, want 5353", cfg.Bind.DNSPort)
		}
		if cfg.Policy.MinTTL != 30 {
			t.Errorf("Load().Policy.MinTTL = %d, want 30", cfg.Policy.MinTTL)
		}
		if cfg.Catalog.Zone != "catalog.example.com." {
			t.Errorf("Load().Catalog.Zone = %q, want catalog.example.com.", cfg.Catalog.Zone)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := Load(filepath.Join(tmpDir, "nonexistent.yaml"))
		if err == nil {
			t.Error("Load() expected error for nonexistent file")
		}
	})

	t.Run("invalid YAML", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(configPath, []byte("{{{{invalid yaml"), 0644); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		_, err := Load(configPath)
		if err == nil {
			t.Error("Load() expected error for invalid YAML")
		}
	})

	t.Run("empty file fails validation", func(t *testing.T) {
		configPath := filepath.Join(tmpDir, "empty.yaml")
		if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		_, err := Load(configPath)
		// Empty file should fail validation (missing catalog.zone, etc.)
		if err == nil {
			t.Error("Load() should fail for empty file due to missing required fields")
		}
	})
}

// helperValidConfig creates a valid config for testing
func helperValidConfig() *Config {
	cfg := DefaultConfig()
	cfg.Catalog.Zone = "catalog.example.com."
	cfg.TSIG.Name = "dnsctl-key."
	cfg.TSIG.Secret = "supersecretkey"
	return cfg
}

// TestValidateConfig tests configuration validation
func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		modifier func(*Config)
		wantErr  bool
	}{
		{
			name:     "valid complete config",
			modifier: func(c *Config) {},
			wantErr:  false,
		},
		{
			name: "empty rndc_path",
			modifier: func(c *Config) {
				c.Bind.RNDCPath = ""
			},
			wantErr: true,
		},
		{
			name: "empty rndc_conf",
			modifier: func(c *Config) {
				c.Bind.RNDCConf = ""
			},
			wantErr: true,
		},
		{
			name: "empty dns_addr",
			modifier: func(c *Config) {
				c.Bind.DNSAddr = ""
			},
			wantErr: true,
		},
		{
			name: "invalid dns_port - zero",
			modifier: func(c *Config) {
				c.Bind.DNSPort = 0
			},
			wantErr: true,
		},
		{
			name: "invalid dns_port - negative",
			modifier: func(c *Config) {
				c.Bind.DNSPort = -1
			},
			wantErr: true,
		},
		{
			name: "invalid dns_port - too high",
			modifier: func(c *Config) {
				c.Bind.DNSPort = 65536
			},
			wantErr: true,
		},
		{
			name: "valid dns_port - max",
			modifier: func(c *Config) {
				c.Bind.DNSPort = 65535
			},
			wantErr: false,
		},
		{
			name: "empty zones dir",
			modifier: func(c *Config) {
				c.Zones.Dir = ""
			},
			wantErr: true,
		},
		{
			name: "empty locking dir",
			modifier: func(c *Config) {
				c.Locking.Dir = ""
			},
			wantErr: true,
		},
		{
			name: "min_ttl greater than max_ttl",
			modifier: func(c *Config) {
				c.Policy.MinTTL = 1000
				c.Policy.MaxTTL = 100
			},
			wantErr: true,
		},
		{
			name: "negative min_ttl",
			modifier: func(c *Config) {
				c.Policy.MinTTL = -1
			},
			wantErr: true,
		},
		{
			name: "missing catalog zone",
			modifier: func(c *Config) {
				c.Catalog.Zone = ""
			},
			wantErr: true,
		},
		{
			name: "catalog zone without trailing dot",
			modifier: func(c *Config) {
				c.Catalog.Zone = "catalog.example.com"
			},
			wantErr: true,
		},
		{
			name: "missing tsig name",
			modifier: func(c *Config) {
				c.TSIG.Name = ""
			},
			wantErr: true,
		},
		{
			name: "missing tsig secret",
			modifier: func(c *Config) {
				c.TSIG.Secret = ""
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := helperValidConfig()
			tt.modifier(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestIsAllowedRRType tests RR type allowlist checking
func TestIsAllowedRRType(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			AllowedRRtypes: []string{"A", "AAAA", "CNAME", "TXT", "MX"},
		},
	}

	tests := []struct {
		rrType string
		want   bool
	}{
		{"A", true},
		{"AAAA", true},
		{"CNAME", true},
		{"TXT", true},
		{"MX", true},
		{"SRV", false},  // Not in allowed list
		{"NS", false},   // Not in allowed list
		{"SOA", false},  // Never allowed
		{"a", true},     // Case insensitive
		{"aaaa", true},  // Case insensitive
		{"Cname", true}, // Case insensitive
		{"", false},     // Empty
	}

	for _, tt := range tests {
		t.Run(tt.rrType, func(t *testing.T) {
			got := cfg.IsAllowedRRType(tt.rrType)
			if got != tt.want {
				t.Errorf("IsAllowedRRType(%q) = %v, want %v", tt.rrType, got, tt.want)
			}
		})
	}
}

// TestValidateTTL tests TTL validation
func TestValidateTTL(t *testing.T) {
	cfg := &Config{
		Policy: PolicyConfig{
			MinTTL: 60,
			MaxTTL: 86400,
		},
	}

	tests := []struct {
		name    string
		ttl     uint32
		wantErr bool
	}{
		{"exactly min TTL", 60, false},
		{"exactly max TTL", 86400, false},
		{"mid range TTL", 3600, false},
		{"below min TTL", 30, true},
		{"above max TTL", 100000, true},
		{"zero TTL", 0, true},
		{"one second TTL", 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfg.ValidateTTL(tt.ttl)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTTL(%d) error = %v, wantErr %v", tt.ttl, err, tt.wantErr)
			}
		})
	}
}

// TestZoneFilePath tests zone file path generation
func TestZoneFilePath(t *testing.T) {
	cfg := &Config{
		Zones: ZonesConfig{
			Dir:           "/var/lib/bind/zones",
			FileExtension: "db",
		},
	}

	tests := []struct {
		zone string
		want string
	}{
		// Implementation removes trailing dot before adding extension
		{"example.com.", "/var/lib/bind/zones/example.com.db"},
		{"www.example.com.", "/var/lib/bind/zones/www.example.com.db"},
		{"test.org.", "/var/lib/bind/zones/test.org.db"},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			got := cfg.ZoneFilePath(tt.zone)
			if got != tt.want {
				t.Errorf("ZoneFilePath(%q) = %q, want %q", tt.zone, got, tt.want)
			}
		})
	}
}

// TestLockFilePath tests lock file path generation
func TestLockFilePath(t *testing.T) {
	cfg := &Config{
		Locking: LockingConfig{
			Dir: "/var/lock/dnsctl",
		},
	}

	tests := []struct {
		zone string
		want string
	}{
		// Implementation removes trailing dot: zone--example.com.lock
		{"example.com.", "/var/lock/dnsctl/zone--example.com.lock"},
		{"www.example.com.", "/var/lock/dnsctl/zone--www.example.com.lock"},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			got := cfg.LockFilePath(tt.zone)
			if got != tt.want {
				t.Errorf("LockFilePath(%q) = %q, want %q", tt.zone, got, tt.want)
			}
		})
	}
}

// TestEnsureDirs tests directory creation
func TestEnsureDirs(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("creates zones and locking directories", func(t *testing.T) {
		cfg := &Config{
			Zones: ZonesConfig{
				Dir: filepath.Join(tmpDir, "zones"),
			},
			Locking: LockingConfig{
				Dir: filepath.Join(tmpDir, "locks"),
			},
		}

		err := cfg.EnsureDirs()
		if err != nil {
			t.Fatalf("EnsureDirs() error = %v", err)
		}

		// Verify directories exist
		if _, err := os.Stat(cfg.Zones.Dir); os.IsNotExist(err) {
			t.Errorf("Zones directory was not created")
		}
		if _, err := os.Stat(cfg.Locking.Dir); os.IsNotExist(err) {
			t.Errorf("Locking directory was not created")
		}
	})

	t.Run("succeeds if directories already exist", func(t *testing.T) {
		cfg := &Config{
			Zones: ZonesConfig{
				Dir: filepath.Join(tmpDir, "existing_zones"),
			},
			Locking: LockingConfig{
				Dir: filepath.Join(tmpDir, "existing_locks"),
			},
		}

		// Create directories first
		os.MkdirAll(cfg.Zones.Dir, 0755)
		os.MkdirAll(cfg.Locking.Dir, 0755)

		err := cfg.EnsureDirs()
		if err != nil {
			t.Fatalf("EnsureDirs() error = %v", err)
		}
	})
}
