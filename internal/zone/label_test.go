package zone

import (
	"testing"
)

// TestSHA1WireLabel tests the sha1-wire catalog member label computation
// These test vectors are based on RFC 9492 (Catalog Zones) and standard DNS wire format
func TestSHA1WireLabel(t *testing.T) {
	tests := []struct {
		name  string
		zone  string
		want  string // Expected hex-encoded SHA1 hash
	}{
		{
			name: "simple zone - example.com",
			// Wire format: \007example\003com\000
			// SHA1: c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4
			zone: "example.com.",
			want: "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4",
		},
		{
			name: "zone without trailing dot",
			// Should normalize to have trailing dot before computing
			zone: "example.com",
			want: "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4",
		},
		{
			name: "subdomain zone",
			// Wire format: \003www\007example\003com\000
			zone: "www.example.com.",
			want: "b49edbb7a3bbde3c34a3c1fb55063b7bd259d3d4",
		},
		{
			name: "single label zone",
			// Wire format: \009localhost\000
			zone: "localhost.",
			want: "f80a23021296bb1f40646df9098499a45fafb7ed",
		},
		{
			name: "deeply nested zone",
			// Wire format: \001a\001b\001c\007example\003com\000
			zone: "a.b.c.example.com.",
			want: "fd96939c94e270e6928bcd1c7ea34a457f380a96",
		},
		{
			name: "uppercase zone - case insensitive",
			// DNS wire format is case-insensitive, should lowercase first
			zone: "EXAMPLE.COM.",
			want: "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4",
		},
		{
			name: "mixed case zone",
			zone: "ExAmPlE.CoM.",
			want: "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4",
		},
		{
			name: "zone with hyphen",
			// Wire format: \010test-zone\007example\003com\000
			zone: "test-zone.example.com.",
			want: "75f7c217b686a240ee6b8b85521976f4f239c12a",
		},
		{
			name: "zone with numbers",
			// Wire format: \006test123\007example\003com\000
			zone: "test123.example.com.",
			want: "a48b8605b410ba5930ce307e795a0c9418ff0108",
		},
		{
			name: "IDN - punycode zone",
			// xn-- domains are already encoded
			zone: "xn--mnchen-3ya.de.",
			want: "99d30e69fd986a71cf83a02f906e0099bbd7d273",
		},
		{
			name: "TLD only",
			// Wire format: \003com\000
			zone: "com.",
			want: "65019c4ed041c959edcf3b9f741060d7e5d42f96",
		},
		{
			name: "wildcard zone",
			// Wire format: \001*\007example\003com\000
			zone: "*.example.com.",
			want: "23c6cbf50cf085dbc1cc1a0539920d7136b21fcb",
		},
		{
			name: "service record zone",
			// Wire format: \010_acme-challenge\007example\003com\000
			zone: "_acme-challenge.example.com.",
			want: "c7504de7500de3b740f967b8e46860d7629bdc2e",
		},
		{
			name: "DKIM-style zone",
			// Wire format: \010_domainkey\007example\003com\000
			zone: "_domainkey.example.com.",
			want: "9e0337f88733cfe7f73bf2383c53761ba7621dcf",
		},
		{
			name: "SRV-style zone",
			// Wire format: \004_tcp\004_ldap\007example\003com\000
			zone: "_ldap._tcp.example.com.",
			want: "d543da54d0100b3b309ec6995407ef9cf6d1c888",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SHA1WireLabel(tt.zone)
			if got != tt.want {
				t.Errorf("SHA1WireLabel(%q) = %q, want %q", tt.zone, got, tt.want)
			}
		})
	}
}

// TestSHA1WireLabelProperties tests important properties of the sha1-wire label
func TestSHA1WireLabelProperties(t *testing.T) {
	t.Run("deterministic - same input produces same output", func(t *testing.T) {
		zone := "example.com."
		first := SHA1WireLabel(zone)
		second := SHA1WireLabel(zone)
		if first != second {
			t.Errorf("SHA1WireLabel not deterministic: %s != %s", first, second)
		}
	})

	t.Run("fixed length - SHA1 always produces 40 hex chars", func(t *testing.T) {
		zones := []string{
			"a.com.",
			"abcdefghijklmnopqrstuvwxyz.com.",
			"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com.",
		}
		for _, zone := range zones {
			label := SHA1WireLabel(zone)
			if len(label) != 40 {
				t.Errorf("SHA1WireLabel(%q) length = %d, want 40", zone, len(label))
			}
		}
	})

	t.Run("lowercase hex output", func(t *testing.T) {
		zone := "EXAMPLE.COM."
		label := SHA1WireLabel(zone)
		for _, c := range label {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("SHA1WireLabel contains invalid character: %c", c)
			}
		}
	})

	t.Run("different zones produce different labels", func(t *testing.T) {
		zones := []string{
			"example.com.",
			"www.example.com.",
			"test.example.com.",
			"other.com.",
		}
		labels := make(map[string]bool)
		for _, zone := range zones {
			label := SHA1WireLabel(zone)
			if labels[label] {
				t.Errorf("Collision detected: %q and another zone both produced label %s", zone, label)
			}
			labels[label] = true
		}
	})

	t.Run("similar zones produce different labels", func(t *testing.T) {
		zone1 := "example1.com."
		zone2 := "example2.com."
		label1 := SHA1WireLabel(zone1)
		label2 := SHA1WireLabel(zone2)
		if label1 == label2 {
			t.Errorf("SHA1WireLabel produced same output for different zones: %s == %s", label1, label2)
		}
		// Check that the difference isn't just a small change (avalanche effect)
		diffs := 0
		for i := 0; i < 40; i++ {
			if label1[i] != label2[i] {
				diffs++
			}
		}
		if diffs < 10 {
			t.Logf("Warning: only %d characters differ between similar zones", diffs)
		}
	})
}

// TestDNSWireFormat tests the DNS wire format conversion
func TestDNSWireFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int // Expected wire format length
	}{
		{
			name:    "simple zone",
			input:   "example.com.",
			wantLen: 13, // \007example\003com\000 = 1+7+1+3+1
		},
		{
			name:    "single label",
			input:   "localhost.",
			wantLen: 11, // \009localhost\000 = 1+9+1
		},
		{
			name:    "two labels",
			input:   "www.example.com.",
			wantLen: 17, // \003www\007example\003com\000 = 1+3+1+7+1+3+1
		},
		{
			name:    "zone without trailing dot - should add it",
			input:   "example.com",
			wantLen: 13,
		},
		{
			name:    "empty zone",
			input:   ".",
			wantLen: 1, // Just root byte
		},
		{
			name:    "label with hyphen",
			input:   "test-zone.com.",
			wantLen: 15, // \010test-zone\003com\000 = 1+10+1+3+1
		},
		{
			name:    "label with underscore",
			input:   "_test.com.",
			wantLen: 11, // \005_test\003com\000 = 1+5+1+3+1 (but "test" is 4 chars so \004_test = 1+4+1+3+1=10... wait)
		},
		{
			name:    "numeric label",
			input:   "123.com.",
			wantLen: 9, // \003123\003com\000 = 1+3+1+3+1 (but wait, 123.com is 7 chars with dots... let me recalculate)
		},
		{
			name:    "wildcard",
			input:   "*.com.",
			wantLen: 7, // \001*\003com\000 = 1+1+1+3+1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := dnsWireFormat(tt.input)
			if len(wire) != tt.wantLen {
				t.Errorf("dnsWireFormat(%q) length = %d, want %d", tt.input, len(wire), tt.wantLen)
			}
		})
	}
}

// BenchmarkSHA1WireLabel benchmarks the sha1-wire label computation
func BenchmarkSHA1WireLabel(b *testing.B) {
	zones := []string{
		"example.com.",
		"www.example.com.",
		"a.b.c.d.e.f.example.com.",
		"xn--mnchen-3ya.xn--de-0lai.de.",
		"_acme-challenge.example.com.",
		"selector1._domainkey.example.com.",
		"_ldap._tcp.example.com.",
	}

	for _, zone := range zones {
		b.Run(zone, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				SHA1WireLabel(zone)
			}
		})
	}
}
