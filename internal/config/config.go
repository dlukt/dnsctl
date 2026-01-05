package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the dnsctl configuration file (spec section 6)
type Config struct {
	Bind    BindConfig    `yaml:"bind"`
	Catalog CatalogConfig `yaml:"catalog"`
	Zones   ZonesConfig   `yaml:"zones"`
	TSIG    TSIGConfig    `yaml:"tsig"`
	Policy  PolicyConfig  `yaml:"policy"`
	Locking LockingConfig `yaml:"locking"`
	Logging LoggingConfig `yaml:"logging"`

	// Path to the config file itself (for resolving relative paths)
	configPath string
}

// BindConfig contains BIND-specific configuration (spec 6.1)
type BindConfig struct {
	RNDCPath  string `yaml:"rndc_path"`  // Path to rndc binary
	RNDCConf  string `yaml:"rndc_conf"`  // Path to rndc.conf
	View      string `yaml:"view"`       // Empty means default view
	DNSAddr   string `yaml:"dns_addr"`   // DNS server address for updates
	DNSPort   int    `yaml:"dns_port"`   // DNS server port
	TCPUpdates bool  `yaml:"tcp_updates"` // Use TCP for updates by default
}

// CatalogConfig contains catalog zone configuration
type CatalogConfig struct {
	Zone           string `yaml:"zone"`            // FQDN with trailing dot
	SchemaVersion  int    `yaml:"schema_version"`  // 1 or 2
	LabelAlgorithm string `yaml:"label_algorithm"` // sha1-wire
}

// ZonesConfig contains zone management configuration
type ZonesConfig struct {
	Dir             string `yaml:"dir"`              // Zone file directory
	FileExtension   string `yaml:"file_extension"`   // Zone file extension (e.g., "zone")
	FileOwner       string `yaml:"file_owner"`       // Zone file owner (e.g., "bind")
	FileGroup       string `yaml:"file_group"`       // Zone file group (e.g., "bind")
	DefaultNotify   bool   `yaml:"default_notify"`   // Default notify setting
	DNSSECPolicy    string `yaml:"dnssec_policy"`    // DNSSEC policy (e.g., "default")
	InlineSigning   bool   `yaml:"inline_signing"`   // Enable inline signing
	UpdateMode      string `yaml:"update_mode"`      // allow-update | update-policy
	TSIGKeyName     string `yaml:"tsig_key_name"`    // TSIG key name as used in BIND
	UpdatePolicyGrant string `yaml:"update_policy_grant"` // For update-policy mode (e.g., "zonesub ANY")
}

// TSIGConfig contains TSIG authentication configuration
type TSIGConfig struct {
	Name       string `yaml:"name"`        // TSIG key name
	Algorithm  string `yaml:"algorithm"`   // TSIG algorithm (e.g., hmac-sha256)
	SecretFile string `yaml:"secret_file"` // Path to TSIG secret file

	// Loaded secret (not in YAML)
	Secret string `yaml:"-"`
}

// PolicyConfig contains policy enforcement settings
type PolicyConfig struct {
	AllowedRRtypes    []string `yaml:"allowed_rrtypes"`    // Allowed RR types
	DisallowApexCNAME bool     `yaml:"disallow_apex_cname"` // Reject CNAME at apex
	DisallowNSUpdates bool     `yaml:"disallow_ns_updates"` // Reject NS updates
	MaxTTL            int      `yaml:"max_ttl"`            // Maximum TTL
	MinTTL            int      `yaml:"min_ttl"`            // Minimum TTL
}

// LockingConfig contains locking configuration
type LockingConfig struct {
	Dir string `yaml:"dir"` // Lock file directory
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	AuditJSONL  string `yaml:"audit_jsonl"`   // Optional JSONL audit log path
	IncludeActor bool   `yaml:"include_actor"` // Include actor in logs
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Bind: BindConfig{
			RNDCPath:   "/usr/sbin/rndc",
			RNDCConf:   "/etc/bind/rndc.conf",
			View:       "",
			DNSAddr:    "127.0.0.1",
			DNSPort:    53,
			TCPUpdates: true,
		},
		Catalog: CatalogConfig{
			SchemaVersion:  2,
			LabelAlgorithm: "sha1-wire",
		},
		Zones: ZonesConfig{
			Dir:             "/var/lib/dnsctl/zones",
			FileExtension:   "zone",
			FileOwner:       "bind",
			FileGroup:       "bind",
			DefaultNotify:   true,
			DNSSECPolicy:    "default",
			InlineSigning:   true,
			UpdateMode:      "allow-update",
			UpdatePolicyGrant: "zonesub ANY",
		},
		TSIG: TSIGConfig{
			Algorithm: "hmac-sha256",
		},
		Policy: PolicyConfig{
			AllowedRRtypes:    []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA"},
			DisallowApexCNAME: true,
			DisallowNSUpdates: true,
			MaxTTL:            86400,
			MinTTL:            30,
		},
		Locking: LockingConfig{
			Dir: "/run/dnsctl/locks",
		},
		Logging: LoggingConfig{
			IncludeActor: true,
		},
	}
}

// Load loads the configuration from a YAML file
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	cfg.configPath = path

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Load TSIG secret
	if cfg.TSIG.SecretFile != "" {
		secret, err := os.ReadFile(cfg.TSIG.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read TSIG secret file: %w", err)
		}
		cfg.TSIG.Secret = strings.TrimSpace(string(secret))
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate BIND config
	if c.Bind.RNDCPath == "" {
		return fmt.Errorf("bind.rndc_path is required")
	}
	if c.Bind.RNDCConf == "" {
		return fmt.Errorf("bind.rndc_conf is required")
	}
	if c.Bind.DNSAddr == "" {
		return fmt.Errorf("bind.dns_addr is required")
	}
	if c.Bind.DNSPort <= 0 || c.Bind.DNSPort > 65535 {
		return fmt.Errorf("bind.dns_port must be between 1 and 65535")
	}

	// Validate catalog config
	if c.Catalog.Zone == "" {
		return fmt.Errorf("catalog.zone is required")
	}
	if !strings.HasSuffix(c.Catalog.Zone, ".") {
		return fmt.Errorf("catalog.zone must end with a trailing dot")
	}
	if c.Catalog.SchemaVersion != 1 && c.Catalog.SchemaVersion != 2 {
		return fmt.Errorf("catalog.schema_version must be 1 or 2")
	}
	if c.Catalog.LabelAlgorithm != "sha1-wire" {
		return fmt.Errorf("catalog.label_algorithm must be 'sha1-wire'")
	}

	// Validate zones config
	if c.Zones.Dir == "" {
		return fmt.Errorf("zones.dir is required")
	}
	if c.Zones.FileExtension == "" {
		return fmt.Errorf("zones.file_extension is required")
	}
	if c.Zones.UpdateMode != "allow-update" && c.Zones.UpdateMode != "update-policy" {
		return fmt.Errorf("zones.update_mode must be 'allow-update' or 'update-policy'")
	}

	// Validate TSIG config
	if c.TSIG.Name == "" {
		return fmt.Errorf("tsig.name is required")
	}
	if c.TSIG.Algorithm == "" {
		return fmt.Errorf("tsig.algorithm is required")
	}
	if c.TSIG.Secret == "" {
		return fmt.Errorf("tsig.secret is required (loaded from secret_file)")
	}

	// Validate policy config
	if c.Policy.MinTTL < 0 {
		return fmt.Errorf("policy.min_ttl must be non-negative")
	}
	if c.Policy.MaxTTL < c.Policy.MinTTL {
		return fmt.Errorf("policy.max_ttl must be >= policy.min_ttl")
	}

	// Validate locking config
	if c.Locking.Dir == "" {
		return fmt.Errorf("locking.dir is required")
	}

	return nil
}

// ZoneFilePath returns the absolute path to a zone file
func (c *Config) ZoneFilePath(zone string) string {
	// Remove trailing dot for filename
	zoneName := strings.TrimSuffix(zone, ".")
	return filepath.Join(c.Zones.Dir, zoneName+"."+c.Zones.FileExtension)
}

// LockFilePath returns the path to a zone lock file
func (c *Config) LockFilePath(zone string) string {
	// Remove trailing dot for filename
	zoneName := strings.TrimSuffix(zone, ".")
	return filepath.Join(c.Locking.Dir, "zone--"+zoneName+".lock")
}

// EnsureDirs creates required directories if they don't exist
func (c *Config) EnsureDirs() error {
	dirs := []string{
		c.Zones.Dir,
		c.Locking.Dir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// IsAllowedRRType checks if an RR type is allowed by policy
func (c *Config) IsAllowedRRType(rrType string) bool {
	for _, allowed := range c.Policy.AllowedRRtypes {
		if strings.EqualFold(rrType, allowed) {
			return true
		}
	}
	return false
}

// ValidateTTL checks if a TTL is within policy limits
func (c *Config) ValidateTTL(ttl uint32) error {
	if int(ttl) < c.Policy.MinTTL {
		return fmt.Errorf("TTL %d is below minimum %d", ttl, c.Policy.MinTTL)
	}
	if int(ttl) > c.Policy.MaxTTL {
		return fmt.Errorf("TTL %d exceeds maximum %d", ttl, c.Policy.MaxTTL)
	}
	return nil
}
