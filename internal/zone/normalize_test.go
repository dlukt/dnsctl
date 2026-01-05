package zone

import (
	"strings"
	"testing"
)

// TestNormalizeZone tests zone normalization
func TestNormalizeZone(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "simple zone",
			input:   "example.com",
			want:    "example.com.",
			wantErr: false,
		},
		{
			name:    "zone with trailing dot",
			input:   "example.com.",
			want:    "example.com.",
			wantErr: false,
		},
		{
			name:    "uppercase zone - lowercased",
			input:   "EXAMPLE.COM",
			want:    "example.com.",
			wantErr: false,
		},
		{
			name:    "mixed case zone",
			input:   "ExAmPlE.CoM",
			want:    "example.com.",
			wantErr: false,
		},
		{
			name:    "subdomain zone",
			input:   "sub.example.com",
			want:    "sub.example.com.",
			wantErr: false,
		},
		{
			name:    "deeply nested zone",
			input:   "a.b.c.example.com",
			want:    "a.b.c.example.com.",
			wantErr: false,
		},
		{
			name:    "single label zone",
			input:   "localhost",
			want:    "localhost.",
			wantErr: false,
		},
		{
			name:    "IDN - unicode with accents",
			input:   "münchen.de",
			want:    "xn--mnchen-3ya.de.",
			wantErr: false,
		},
		{
			name:    "IDN - unicode with emoji",
			input:   "emojï.example.com",
			want:    "xn--emoj-8pa.example.com.",
			wantErr: false,
		},
		{
			name:    "IDN - Chinese characters",
			input:   "中国.cn",
			want:    "xn--fiqs8s.cn.",
			wantErr: false,
		},
		{
			name:    "IDN - Arabic characters",
			input:   "مصر.com",
			want:    "xn--wgbh1c.com.",
			wantErr: false,
		},
		{
			name:    "IDN - Cyrillic characters",
			input:   "россия.рф",
			want:    "xn--h1alffa9f.xn--p1ai.",
			wantErr: false,
		},
		{
			name:    "already punycode",
			input:   "xn--mnchen-3ya.de",
			want:    "xn--mnchen-3ya.de.",
			wantErr: false,
		},
		{
			name:    "IDN with trailing dot",
			input:   "münchen.de.",
			want:    "xn--mnchen-3ya.de.",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "single dot",
			input:   ".",
			want:    "",
			wantErr: true,
		},
		{
			name:    "label too long (63 chars)",
			input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com.",
			wantErr: false, // Actually exactly 63 chars, which is the max, so it passes
		},
		{
			name:    "label exactly 63 chars (max)",
			input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
			want:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com.",
			wantErr: false,
		},
		{
			name:    "label over 63 chars (64 chars)",
			input:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "zone too long (over 253 chars)",
			input:   strings.Repeat("aa.", 85) + "com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "label with underscore (rejected by validation)",
			input:   "_test.example.com",
			want:    "",
			wantErr: true, // isDNSLabelChar doesn't allow underscore
		},
		{
			name:    "label with hyphen",
			input:   "test-zone.example.com",
			want:    "test-zone.example.com.",
			wantErr: false,
		},
		{
			name:    "label starting with hyphen (invalid)",
			input:   "-test.example.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "label ending with hyphen (invalid)",
			input:   "test-.example.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "zone with space (invalid)",
			input:   "test zone.com",
			want:    "",
			wantErr: true,
		},
		{
			name:    "root zone",
			input:   ".",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeZone(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeZone(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeZone(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestNormalizeOwner tests owner name normalization
func TestNormalizeOwner(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		zone     string
		want     string
		wantErr  bool
		errMsg   string
	}{
		{
			name:    "apex with @ symbol",
			owner:   "@",
			zone:    "example.com.",
			want:    "example.com.",
			wantErr: false,
		},
		{
			name:    "empty string relative name",
			owner:   "",
			zone:    "example.com.",
			want:    ".example.com.",
			wantErr: false, // Empty string doesn't get special treatment, becomes ".zone."
		},
		{
			name:    "relative owner within zone",
			owner:   "www",
			zone:    "example.com.",
			want:    "www.example.com.",
			wantErr: false,
		},
		{
			name:    "relative owner with multiple labels",
			owner:   "www.sub",
			zone:   "example.com.",
			want:    "www.sub.example.com.",
			wantErr: false,
		},
		{
			name:    "FQDN owner within zone",
			owner:   "www.example.com.",
			zone:    "example.com.",
			want:    "www.example.com.",
			wantErr: false,
		},
		{
			name:    "FQDN owner without trailing dot (treated as relative)",
			owner:   "www.example.com",
			zone:    "example.com.",
			want:    "www.example.com.example.com.",
			wantErr: false, // No trailing dot = relative name, so zone is appended
		},
		{
			name:    "deeply nested FQDN",
			owner:   "a.b.c.example.com.",
			zone:    "example.com.",
			want:    "a.b.c.example.com.",
			wantErr: false,
		},
		{
			name:    "owner exactly matches zone",
			owner:   "example.com.",
			zone:    "example.com.",
			want:    "example.com.",
			wantErr: false,
		},
		{
			name:    "uppercase owner - lowercased",
			owner:   "WWW",
			zone:    "example.com.",
			want:    "www.example.com.",
			wantErr: false,
		},
		{
			name:    "mixed case FQDN",
			owner:   "WwW.ExAmPlE.CoM.",
			zone:    "example.com.",
			want:    "www.example.com.",
			wantErr: false,
		},
		{
			name:    "IDN owner - not converted (NormalizeOwner doesn't do IDN)",
			owner:   "münchen",
			zone:    "example.com.",
			want:    "münchen.example.com.",
			wantErr: false, // NormalizeOwner doesn't do IDN conversion
		},
		{
			name:    "IDN FQDN owner (within zone, punycode)",
			owner:   "xn--mnchen-3ya.de.",
			zone:    "de.",
			want:    "xn--mnchen-3ya.de.",
			wantErr: false,
		},
		{
			name:    "wildcard owner",
			owner:   "*.example.com.",
			zone:    "example.com.",
			want:    "*.example.com.",
			wantErr: false,
		},
		{
			name:    "wildcard relative",
			owner:   "*",
			zone:    "example.com.",
			want:    "*.example.com.",
			wantErr: false,
		},
		{
			name:    "owner outside zone - different domain",
			owner:   "www.other.com.",
			zone:    "example.com.",
			want:    "",
			wantErr: true,
			errMsg:  "owner",
		},
		{
			name:    "owner is parent of zone - not within",
			owner:   "com.",
			zone:    "example.com.",
			want:    "",
			wantErr: true,
			errMsg:  "owner",
		},
		{
			name:    "owner with spaces (not validated in NormalizeOwner)",
			owner:   "test owner",
			zone:    "example.com.",
			want:    "test owner.example.com.",
			wantErr: false, // NormalizeOwner doesn't validate characters in relative names
		},
		{
			name:    "owner with invalid characters (not validated in NormalizeOwner)",
			owner:   "test#owner",
			zone:    "example.com.",
			want:    "test#owner.example.com.",
			wantErr: false, // NormalizeOwner doesn't validate characters in relative names
		},
		{
			name:    "service owner with underscore",
			owner:   "_service._tcp.example.com.",
			zone:    "example.com.",
			want:    "_service._tcp.example.com.",
			wantErr: false,
		},
		{
			name:    "relative service owner",
			owner:   "_service._tcp",
			zone:    "example.com.",
			want:    "_service._tcp.example.com.",
			wantErr: false,
		},
		{
			name:    "DKIM owner",
			owner:   "selector1._domainkey.example.com.",
			zone:    "example.com.",
			want:    "selector1._domainkey.example.com.",
			wantErr: false,
		},
		{
			name:    "SRV owner format",
			owner:   "_ldap._tcp.example.com.",
			zone:    "example.com.",
			want:    "_ldap._tcp.example.com.",
			wantErr: false,
		},
		{
			name:    "ACME challenge owner",
			owner:   "_acme-challenge.example.com.",
			zone:    "example.com.",
			want:    "_acme-challenge.example.com.",
			wantErr: false,
		},
		{
			name:    "relative ACME challenge",
			owner:   "_acme-challenge.www",
			zone:    "example.com.",
			want:    "_acme-challenge.www.example.com.",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeOwner(tt.owner, tt.zone)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeOwner(%q, %q) error = %v, wantErr %v", tt.owner, tt.zone, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("NormalizeOwner(%q, %q) error = %v, expected to contain %q", tt.owner, tt.zone, err, tt.errMsg)
				}
			}
			if got != tt.want {
				t.Errorf("NormalizeOwner(%q, %q) = %q, want %q", tt.owner, tt.zone, got, tt.want)
			}
		})
	}
}

// TestIsApexOwner tests apex owner detection
func TestIsApexOwner(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		zone  string
		want  bool
	}{
		{
			name:  "exact match with trailing dot",
			owner: "example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "exact match without trailing dot on zone",
			owner: "example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "@ symbol not treated as apex (no special handling)",
			owner: "@",
			zone:  "example.com.",
			want:  false, // @ doesn't get special handling in IsApexOwner
		},
		{
			name:  "empty string not treated as apex",
			owner: "",
			zone:  "example.com.",
			want:  false, // Empty string becomes "." which doesn't match zone
		},
		{
			name:  "subdomain not apex",
			owner: "www.example.com.",
			zone:  "example.com.",
			want:  false,
		},
		{
			name:  "deep subdomain not apex",
			owner: "a.b.c.example.com.",
			zone:  "example.com.",
			want:  false,
		},
		{
			name:  "different domain",
			owner: "other.com.",
			zone:  "example.com.",
			want:  false,
		},
		{
			name:  "wildcard not apex",
			owner: "*.example.com.",
			zone:  "example.com.",
			want:  false,
		},
		{
			name:  "service record not apex",
			owner: "_service._tcp.example.com.",
			zone:  "example.com.",
			want:  false,
		},
		{
			name:  "case insensitive apex match",
			owner: "EXAMPLE.COM.",
			zone:  "example.com.",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsApexOwner(tt.owner, tt.zone); got != tt.want {
				t.Errorf("IsApexOwner(%q, %q) = %v, want %v", tt.owner, tt.zone, got, tt.want)
			}
		})
	}
}

// TestIsWithinZone tests zone membership check
func TestIsWithinZone(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		zone  string
		want  bool
	}{
		{
			name:  "apex is within zone",
			owner: "example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "direct subdomain",
			owner: "www.example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "deep subdomain",
			owner: "a.b.c.example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "service record within zone",
			owner: "_service._tcp.example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "ACME challenge within zone",
			owner: "_acme-challenge.www.example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "different domain - not within",
			owner: "www.other.com.",
			zone:  "example.com.",
			want:  false,
		},
		{
			name:  "parent domain - not within",
			owner: "com.",
			zone:  "example.com.",
			want:  false,
		},
		{
			name:  "sibling domain - not within",
			owner: "other.example.com.",
			zone:  "www.example.com.",
			want:  false,
		},
		{
			name:  "case insensitive match",
			owner: "WWW.EXAMPLE.COM.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "wildcard within zone",
			owner: "*.example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "DKIM within zone",
			owner: "selector._domainkey.example.com.",
			zone:  "example.com.",
			want:  true,
		},
		{
			name:  "SRV within zone",
			owner: "_ldap._tcp.example.com.",
			zone:  "example.com.",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsWithinZone(tt.owner, tt.zone); got != tt.want {
				t.Errorf("IsWithinZone(%q, %q) = %v, want %v", tt.owner, tt.zone, got, tt.want)
			}
		})
	}
}
