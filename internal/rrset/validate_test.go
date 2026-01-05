package rrset

import (
	"testing"

	"github.com/dlukt/dnsctl/internal/config"
)

// mockConfig creates a minimal config for testing
func mockConfig() *config.Config {
	return &config.Config{
		Policy: config.PolicyConfig{
			AllowedRRtypes:    []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA", "NS"},
			MinTTL:            60,
			MaxTTL:            86400,
			DisallowApexCNAME: true,
			DisallowNSUpdates: true,
		},
	}
}

// TestValidateA tests A record validation
func TestValidateA(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			rdata:   []string{"192.0.2.1"},
			wantErr: false,
		},
		{
			name:    "valid IPv4 - private network",
			rdata:   []string{"10.0.0.1"},
			wantErr: false,
		},
		{
			name:    "valid IPv4 - loopback",
			rdata:   []string{"127.0.0.1"},
			wantErr: false,
		},
		{
			name:    "multiple valid A records",
			rdata:   []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
			wantErr: false,
		},
		{
			name:    "IPv6 address in A record",
			rdata:   []string{"2001:db8::1"},
			wantErr: true,
		},
		{
			name:    "invalid IP address",
			rdata:   []string{"not.an.ip.address"},
			wantErr: true,
		},
		{
			name:    "IP out of range",
			rdata:   []string{"256.256.256.256"},
			wantErr: true,
		},
		{
			name:    "empty string",
			rdata:   []string{""},
			wantErr: true,
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
		{
			name:    "IP with port",
			rdata:   []string{"192.0.2.1:8080"},
			wantErr: true,
		},
		{
			name:    "CIDR notation",
			rdata:   []string{"192.0.2.0/24"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateA(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateA(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateAAAA tests AAAA record validation
func TestValidateAAAA(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid IPv6 - full form",
			rdata:   []string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
			wantErr: false,
		},
		{
			name:    "valid IPv6 - compressed form",
			rdata:   []string{"2001:db8::1"},
			wantErr: false,
		},
		{
			name:    "valid IPv6 - loopback",
			rdata:   []string{"::1"},
			wantErr: false,
		},
		{
			name:    "valid IPv6 - link local",
			rdata:   []string{"fe80::1"},
			wantErr: false,
		},
		{
			name:    "multiple AAAA records",
			rdata:   []string{"2001:db8::1", "2001:db8::2"},
			wantErr: false,
		},
		{
			name:    "IPv4 address in AAAA record",
			rdata:   []string{"192.0.2.1"},
			wantErr: true,
		},
		{
			name:    "invalid IPv6",
			rdata:   []string{"not-an-ipv6"},
			wantErr: true,
		},
		{
			name:    "IPv6 with zone ID",
			rdata:   []string{"fe80::1%eth0"},
			wantErr: true, // zone ID not allowed in DNS
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
		{
			name:    "IPv6 with port",
			rdata:   []string{"[2001:db8::1]:8080"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateAAAA(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAAAA(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateCNAME tests CNAME record validation
func TestValidateCNAME(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid CNAME - simple",
			rdata:   []string{"www.example.com."},
			wantErr: false,
		},
		{
			name:    "valid CNAME - without trailing dot",
			rdata:   []string{"www.example.com"},
			wantErr: false,
		},
		{
			name:    "valid CNAME - external target",
			rdata:   []string{"www.other.com."},
			wantErr: false,
		},
		{
			name:    "empty target",
			rdata:   []string{""},
			wantErr: true,
		},
		{
			name:    "whitespace only",
			rdata:   []string{"   "},
			wantErr: true,
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
		{
			name:    "multiple targets (should only use first)",
			rdata:   []string{"target1.example.com.", "target2.example.com."},
			wantErr: false, // Only validates first element
		},
		{
			name:    "target with spaces",
			rdata:   []string{" target.example.com. "},
			wantErr: false, // Trims whitespace
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateCNAME(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCNAME(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateTXT tests TXT record validation
func TestValidateTXT(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "simple text",
			rdata:   []string{"hello world"},
			wantErr: false,
		},
		{
			name:    "empty string",
			rdata:   []string{""},
			wantErr: false, // Empty TXT is technically valid
		},
		{
			name:    "SPF record",
			rdata:   []string{"v=spf1 ip4:192.0.2.0/24 -all"},
			wantErr: false,
		},
		{
			name:    "DKIM record",
			rdata:   []string{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA..."},
			wantErr: false,
		},
		{
			name:    "long text",
			rdata:   []string{string(make([]byte, 255))},
			wantErr: false,
		},
		{
			name:    "special characters",
			rdata:   []string{"!@#$%^&*()_+-=[]{}|;':\",./<>?"},
			wantErr: false,
		},
		{
			name:    "unicode text",
			rdata:   []string{"Hello 世界 🌍"},
			wantErr: false,
		},
		{
			name:    "multiple TXT strings",
			rdata:   []string{"part1", "part2", "part3"},
			wantErr: false,
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
		{
			name:    "quoted string",
			rdata:   []string{"\"quoted\""},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateTXT(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTXT(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateMX tests MX record validation
func TestValidateMX(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid MX",
			rdata:   []string{"10 mail.example.com."},
			wantErr: false,
		},
		{
			name:    "valid MX - without trailing dot",
			rdata:   []string{"10 mail.example.com"},
			wantErr: false,
		},
		{
			name:    "multiple MX records",
			rdata:   []string{"10 mail1.example.com.", "20 mail2.example.com."},
			wantErr: false,
		},
		{
			name:    "preference 0 (minimum)",
			rdata:   []string{"0 mail.example.com."},
			wantErr: false,
		},
		{
			name:    "preference 65535 (maximum)",
			rdata:   []string{"65535 mail.example.com."},
			wantErr: false,
		},
		{
			name:    "missing preference",
			rdata:   []string{"mail.example.com."},
			wantErr: true,
		},
		{
			name:    "missing host",
			rdata:   []string{"10"},
			wantErr: true,
		},
		{
			name:    "invalid preference - negative",
			rdata:   []string{"-1 mail.example.com."},
			wantErr: true,
		},
		{
			name:    "invalid preference - too large",
			rdata:   []string{"65536 mail.example.com."},
			wantErr: true,
		},
		{
			name:    "invalid preference - non-numeric",
			rdata:   []string{"ten mail.example.com."},
			wantErr: true,
		},
		{
			name:    "empty host",
			rdata:   []string{"10 "},
			wantErr: true,
		},
		{
			name:    "whitespace format",
			rdata:   []string{"10\tmail.example.com."},
			wantErr: false, // strings.Fields handles tabs
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateMX(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMX(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateSRV tests SRV record validation
func TestValidateSRV(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid SRV",
			rdata:   []string{"10 60 443 tls.example.com."},
			wantErr: false,
		},
		{
			name:    "valid SRV - without trailing dot",
			rdata:   []string{"10 60 443 tls.example.com"},
			wantErr: false,
		},
		{
			name:    "LDAP service",
			rdata:   []string{"0 100 389 ldap.example.com."},
			wantErr: false,
		},
		{
			name:    "zero priority (highest)",
			rdata:   []string{"0 0 53 service.example.com."},
			wantErr: false,
		},
		{
			name:    "maximum values",
			rdata:   []string{"65535 65535 65535 service.example.com."},
			wantErr: false,
		},
		{
			name:    "missing priority",
			rdata:   []string{"60 443 service.example.com."},
			wantErr: true,
		},
		{
			name:    "missing weight",
			rdata:   []string{"10 443 service.example.com."},
			wantErr: true,
		},
		{
			name:    "missing port",
			rdata:   []string{"10 60 service.example.com."},
			wantErr: true,
		},
		{
			name:    "missing target",
			rdata:   []string{"10 60 443"},
			wantErr: true,
		},
		{
			name:    "invalid priority - non-numeric",
			rdata:   []string{"high 60 443 service.example.com."},
			wantErr: true,
		},
		{
			name:    "priority out of range",
			rdata:   []string{"65536 60 443 service.example.com."},
			wantErr: true,
		},
		{
			name:    "empty target",
			rdata:   []string{"10 60 443 "},
			wantErr: true,
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateSRV(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSRV(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateCAA tests CAA record validation
func TestValidateCAA(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid CAA - issue",
			rdata:   []string{"0 issue \"letsencrypt.org\""},
			wantErr: false,
		},
		{
			name:    "valid CAA - issuewild",
			rdata:   []string{"0 issuewild \"letsencrypt.org\""},
			wantErr: false,
		},
		{
			name:    "valid CAA - iodef",
			rdata:   []string{"0 iodef \"mailto:security@example.com\""},
			wantErr: false,
		},
		{
			name:    "valid CAA - flag 1 (critical)",
			rdata:   []string{"1 issue \"ca.example.com\""},
			wantErr: false,
		},
		{
			name:    "CAA with value spaces",
			rdata:   []string{"0 issue \"ca.example.com; account=123\""},
			wantErr: false,
		},
		{
			name:    "multiple CAA records",
			rdata:   []string{"0 issue \"letsencrypt.org\"", "0 issuewild \";\""},
			wantErr: false,
		},
		{
			name:    "missing flags",
			rdata:   []string{"issue \"letsencrypt.org\""},
			wantErr: true,
		},
		{
			name:    "missing tag",
			rdata:   []string{"0 \"letsencrypt.org\""},
			wantErr: true,
		},
		{
			name:    "missing value",
			rdata:   []string{"0 issue"},
			wantErr: true,
		},
		{
			name:    "invalid flag - not a number",
			rdata:   []string{"high issue \"letsencrypt.org\""},
			wantErr: true,
		},
		{
			name:    "invalid flag - 2",
			rdata:   []string{"2 issue \"letsencrypt.org\""},
			wantErr: true,
		},
		{
			name:    "invalid flag - negative",
			rdata:   []string{"-1 issue \"letsencrypt.org\""},
			wantErr: true,
		},
		{
			name:    "invalid tag",
			rdata:   []string{"0 invalid \"letsencrypt.org\""},
			wantErr: true,
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateCAA(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCAA(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateNS tests NS record validation
func TestValidateNS(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid NS",
			rdata:   []string{"ns1.example.com."},
			wantErr: false,
		},
		{
			name:    "valid NS - without trailing dot",
			rdata:   []string{"ns1.example.com"},
			wantErr: false,
		},
		{
			name:    "multiple NS records",
			rdata:   []string{"ns1.example.com.", "ns2.example.com.", "ns3.example.com."},
			wantErr: false,
		},
		{
			name:    "root nameserver",
			rdata:   []string{"a.root-servers.net."},
			wantErr: false,
		},
		{
			name:    "empty string",
			rdata:   []string{""},
			wantErr: true,
		},
		{
			name:    "whitespace only",
			rdata:   []string{"   "},
			wantErr: true,
		},
		{
			name:    "no rdata",
			rdata:   []string{},
			wantErr: true,
		},
		{
			name:    "with trailing whitespace",
			rdata:   []string{"ns1.example.com. "},
			wantErr: false, // Gets trimmed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.validateNS(tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateNS(%v) error = %v, wantErr %v", tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRDATA tests the main ValidateRDATA function
func TestValidateRDATA(t *testing.T) {
	cfg := mockConfig()
	v := NewValidator(cfg)

	tests := []struct {
		name    string
		rrType  string
		rdata   []string
		wantErr bool
	}{
		{
			name:    "valid A record",
			rrType:  "A",
			rdata:   []string{"192.0.2.1"},
			wantErr: false,
		},
		{
			name:    "valid AAAA record",
			rrType:  "AAAA",
			rdata:   []string{"2001:db8::1"},
			wantErr: false,
		},
		{
			name:    "valid CNAME record",
			rrType:  "CNAME",
			rdata:   []string{"target.example.com."},
			wantErr: false,
		},
		{
			name:    "valid TXT record",
			rrType:  "TXT",
			rdata:   []string{"v=spf1 -all"},
			wantErr: false,
		},
		{
			name:    "valid MX record",
			rrType:  "MX",
			rdata:   []string{"10 mail.example.com."},
			wantErr: false,
		},
		{
			name:    "valid SRV record",
			rrType:  "SRV",
			rdata:   []string{"10 60 443 service.example.com."},
			wantErr: false,
		},
		{
			name:    "valid CAA record",
			rrType:  "CAA",
			rdata:   []string{"0 issue \"letsencrypt.org\""},
			wantErr: false,
		},
		{
			name:    "valid NS record",
			rrType:  "NS",
			rdata:   []string{"ns1.example.com."},
			wantErr: false,
		},
		{
			name:    "case insensitive type",
			rrType:  "a",
			rdata:   []string{"192.0.2.1"},
			wantErr: false,
		},
		{
			name:    "no rdata provided",
			rrType:  "A",
			rdata:   []string{},
			wantErr: true,
		},
		{
			name:    "disallowed type - SOA",
			rrType:  "SOA",
			rdata:   []string{"ns1.example.com. hostmaster.example.com. 1 3600 1800 604800 86400"},
			wantErr: true,
		},
		{
			name:    "unknown type - not allowed by config",
			rrType:  "TYPE1234",
			rdata:   []string{"somedata"},
			wantErr: true, // Unknown types fail allowed type check
		},
		{
			name:    "invalid A data",
			rrType:  "A",
			rdata:   []string{"not-an-ip"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidateRDATA(tt.rrType, tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRDATA(%q, %v) error = %v, wantErr %v", tt.rrType, tt.rdata, err, tt.wantErr)
			}
		})
	}
}

// TestBuildRR tests resource record building
func TestBuildRR(t *testing.T) {
	tests := []struct {
		name    string
		owner   string
		rrType  string
		ttl     uint32
		rdata   string
		wantErr bool
	}{
		{
			name:    "build A record",
			owner:   "www.example.com.",
			rrType:  "A",
			ttl:     3600,
			rdata:   "192.0.2.1",
			wantErr: false,
		},
		{
			name:    "build AAAA record",
			owner:   "www.example.com.",
			rrType:  "AAAA",
			ttl:     3600,
			rdata:   "2001:db8::1",
			wantErr: false,
		},
		{
			name:    "build CNAME record",
			owner:   "www.example.com.",
			rrType:  "CNAME",
			ttl:     3600,
			rdata:   "target.example.com.",
			wantErr: false,
		},
		{
			name:    "build TXT record",
			owner:   "www.example.com.",
			rrType:  "TXT",
			ttl:     3600,
			rdata:   "v=spf1 -all",
			wantErr: false,
		},
		{
			name:    "build MX record",
			owner:   "example.com.",
			rrType:  "MX",
			ttl:     3600,
			rdata:   "10 mail.example.com.",
			wantErr: false,
		},
		{
			name:    "build SRV record",
			owner:   "_ldap._tcp.example.com.",
			rrType:  "SRV",
			ttl:     3600,
			rdata:   "10 60 389 ldap.example.com.",
			wantErr: false,
		},
		{
			name:    "build CAA record",
			owner:   "example.com.",
			rrType:  "CAA",
			ttl:     3600,
			rdata:   "0 issue \"letsencrypt.org\"",
			wantErr: false,
		},
		{
			name:    "build NS record",
			owner:   "example.com.",
			rrType:  "NS",
			ttl:     3600,
			rdata:   "ns1.example.com.",
			wantErr: false,
		},
		{
			name:    "unsupported type",
			owner:   "example.com.",
			rrType:  "SOA",
			ttl:     3600,
			rdata:   "ns1.example.com. hostmaster.example.com. 1 3600 1800 604800 86400",
			wantErr: true,
		},
		{
			name:    "invalid MX format",
			owner:   "example.com.",
			rrType:  "MX",
			ttl:     3600,
			rdata:   "mail.example.com.",
			wantErr: true,
		},
		{
			name:    "invalid SRV format",
			owner:   "_service.example.com.",
			rrType:  "SRV",
			ttl:     3600,
			rdata:   "target.example.com.",
			wantErr: true,
		},
		{
			name:    "invalid CAA format",
			owner:   "example.com.",
			rrType:  "CAA",
			ttl:     3600,
			rdata:   "letsencrypt.org",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := BuildRR(tt.owner, tt.rrType, tt.ttl, tt.rdata)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildRR(%q, %q, %d, %q) error = %v, wantErr %v",
					tt.owner, tt.rrType, tt.ttl, tt.rdata, err, tt.wantErr)
			}
			if !tt.wantErr && rr == nil {
				t.Error("BuildRR returned nil RR without error")
			}
		})
	}
}
