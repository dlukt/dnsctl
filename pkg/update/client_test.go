package update

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestNewClient tests update client creation
func TestNewClient(t *testing.T) {
	tests := []struct {
		name          string
		server        string
		tsigName      string
		tsigSecret    string
		tsigAlgorithm string
	}{
		{
			name:          "basic client",
			server:        "127.0.0.1:53",
			tsigName:      "dnsctl.",
			tsigSecret:    "secret123",
			tsigAlgorithm: "hmac-sha256",
		},
		{
			name:          "client without TSIG",
			server:        "192.168.1.1:53",
			tsigName:      "",
			tsigSecret:    "",
			tsigAlgorithm: "",
		},
		{
			name:          "client with different algorithm",
			server:        "10.0.0.1:5353",
			tsigName:      "update-key.",
			tsigSecret:    "base64secret==",
			tsigAlgorithm: "hmac-sha512",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.server, tt.tsigName, tt.tsigSecret, tt.tsigAlgorithm)

			if client == nil {
				t.Fatal("NewClient() returned nil")
			}

			if client.server != tt.server {
				t.Errorf("server = %q, want %q", client.server, tt.server)
			}
			if client.tsigName != tt.tsigName {
				t.Errorf("tsigName = %q, want %q", client.tsigName, tt.tsigName)
			}
			if client.tsigSecret != tt.tsigSecret {
				t.Errorf("tsigSecret = %q, want %q", client.tsigSecret, tt.tsigSecret)
			}
			if client.tsigAlgorithm != tt.tsigAlgorithm {
				t.Errorf("tsigAlgorithm = %q, want %q", client.tsigAlgorithm, tt.tsigAlgorithm)
			}

			// Default should use TCP
			if !client.useTCP {
				t.Error("useTCP should default to true")
			}
		})
	}
}

// TestSetTCP tests TCP/UDP configuration
func TestSetTCP(t *testing.T) {
	client := NewClient("127.0.0.1:53", "", "", "")

	// Default is TCP
	if !client.useTCP {
		t.Error("Default should be TCP")
	}

	client.SetTCP(false)
	if client.useTCP {
		t.Error("After SetTCP(false), useTCP should be false")
	}

	client.SetTCP(true)
	if !client.useTCP {
		t.Error("After SetTCP(true), useTCP should be true")
	}
}

// TestSetTimeout tests timeout configuration
func TestSetTimeout(t *testing.T) {
	client := NewClient("127.0.0.1:53", "", "", "")

	// Default timeout
	if client.timeout != 30*time.Second {
		t.Errorf("Default timeout = %v, want 30s", client.timeout)
	}

	client.SetTimeout(60 * time.Second)
	if client.timeout != 60*time.Second {
		t.Errorf("After SetTimeout(60s), timeout = %v, want 60s", client.timeout)
	}
}

// TestBuildPTRUpdate tests catalog PTR update message building
func TestBuildPTRUpdate(t *testing.T) {
	tests := []struct {
		name        string
		catalogZone string
		memberZone  string
		label       string
		ttl         uint32
		wantErr     bool
	}{
		{
			name:        "simple catalog update",
			catalogZone: "catalog.example.",
			memberZone:  "member.example.",
			label:       "abc123def456",
			ttl:         60,
			wantErr:     false,
		},
		{
			name:        "SHA1 label",
			catalogZone: "catalog.example.com.",
			memberZone:  "zone.example.com.",
			label:       "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4",
			ttl:         120,
			wantErr:     false,
		},
		{
			name:        "short TTL",
			catalogZone: "catalog.",
			memberZone:  "zone.",
			label:       "shortlabel",
			ttl:         1,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := BuildPTRUpdate(tt.catalogZone, tt.memberZone, tt.label, tt.ttl)

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildPTRUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if msg == nil {
				t.Fatal("BuildPTRUpdate() returned nil message")
			}

			// Verify it's an update message
			if msg.Opcode != dns.OpcodeUpdate {
				t.Errorf("Opcode = %v, want %v (update)", msg.Opcode, dns.OpcodeUpdate)
			}

			// Verify zone section
			if len(msg.Question) != 1 {
				t.Errorf("Question section length = %d, want 1", len(msg.Question))
			} else {
				if msg.Question[0].Name != dns.Fqdn(tt.catalogZone) {
					t.Errorf("Zone = %q, want %q", msg.Question[0].Name, dns.Fqdn(tt.catalogZone))
				}
			}

			// Verify update section contains PTR record
			foundPTR := false
			expectedOwner := dns.Fqdn(tt.label + ".zones." + tt.catalogZone)
			for _, rr := range msg.Ns {
				if ptr, ok := rr.(*dns.PTR); ok {
					foundPTR = true
					if ptr.Header().Name != expectedOwner {
						t.Errorf("PTR owner = %q, want %q", ptr.Header().Name, expectedOwner)
					}
					if ptr.Ptr != dns.Fqdn(tt.memberZone) {
						t.Errorf("PTR target = %q, want %q", ptr.Ptr, dns.Fqdn(tt.memberZone))
					}
					if ptr.Header().Ttl != tt.ttl {
						t.Errorf("PTR TTL = %d, want %d", ptr.Header().Ttl, tt.ttl)
					}
				}
			}

			if !foundPTR {
				t.Error("BuildPTRUpdate() should include a PTR record in the update section")
			}
		})
	}
}

// TestBuildPTRDelete tests catalog PTR delete message building
func TestBuildPTRDelete(t *testing.T) {
	tests := []struct {
		name        string
		catalogZone string
		label       string
		wantErr     bool
	}{
		{
			name:        "simple delete",
			catalogZone: "catalog.example.",
			label:       "abc123def456",
			wantErr:     false,
		},
		{
			name:        "SHA1 label delete",
			catalogZone: "catalog.example.com.",
			label:       "c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := BuildPTRDelete(tt.catalogZone, tt.label)

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildPTRDelete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if msg == nil {
				t.Fatal("BuildPTRDelete() returned nil message")
			}

			// Verify it's an update message
			if msg.Opcode != dns.OpcodeUpdate {
				t.Errorf("Opcode = %v, want %v (update)", msg.Opcode, dns.OpcodeUpdate)
			}

			// Verify zone section
			if len(msg.Question) != 1 {
				t.Errorf("Question section length = %d, want 1", len(msg.Question))
			} else {
				if msg.Question[0].Name != dns.Fqdn(tt.catalogZone) {
					t.Errorf("Zone = %q, want %q", msg.Question[0].Name, dns.Fqdn(tt.catalogZone))
				}
			}

			// Verify delete section contains RRset removal
			expectedOwner := dns.Fqdn(tt.label + ".zones." + tt.catalogZone)
			foundDelete := false
			for _, rr := range msg.Ns {
				if rr.Header().Name == expectedOwner && rr.Header().Rrtype == dns.TypePTR {
					foundDelete = true
					// For deletions, Class should be ClassANY
					if rr.Header().Class != dns.ClassANY {
						t.Errorf("Delete RR class = %d, want %d (ANY)", rr.Header().Class, dns.ClassANY)
					}
				}
			}

			if !foundDelete {
				t.Error("BuildPTRDelete() should include a PTR RRset removal")
			}
		})
	}
}

// TestPTRUpdateIdempotency tests that PTR update includes delete for idempotency
func TestPTRUpdateIdempotency(t *testing.T) {
	msg, err := BuildPTRUpdate("catalog.example.", "member.example.", "label123", 60)
	if err != nil {
		t.Fatalf("BuildPTRUpdate() error = %v", err)
	}

	// The update should include both delete (for idempotency) and insert
	hasDelete := false
	hasInsert := false

	for _, rr := range msg.Ns {
		header := rr.Header()
		if header.Rrtype == dns.TypePTR {
			if header.Class == dns.ClassANY && header.Ttl == 0 {
				hasDelete = true
			} else if header.Class == dns.ClassINET {
				hasInsert = true
			}
		}
	}

	// Per RFC2136, for idempotent replace we delete first then add
	if !hasDelete {
		t.Error("BuildPTRUpdate() should include delete for idempotency")
	}
	if !hasInsert {
		t.Error("BuildPTRUpdate() should include insert")
	}
}
