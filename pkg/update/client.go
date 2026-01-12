// Package update provides RFC2136 dynamic DNS update functionality with TSIG authentication.
package update

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Client provides RFC2136 dynamic update functionality with TSIG authentication
type Client struct {
	server    string // DNS server address (e.g., "127.0.0.1:53")
	tsigName  string // TSIG key name
	tsigSecret string // TSIG key secret
	tsigAlgorithm string // TSIG algorithm (e.g., "hmac-sha256")
	useTCP    bool   // Use TCP instead of UDP
	timeout   time.Duration
}

// NewClient creates a new RFC2136 update client
func NewClient(server, tsigName, tsigSecret, tsigAlgorithm string) *Client {
	return &Client{
		server:    server,
		tsigName:  tsigName,
		tsigSecret: tsigSecret,
		tsigAlgorithm: tsigAlgorithm,
		useTCP:    true, // Default to TCP as per spec
		timeout:   30 * time.Second,
	}
}

// SetTCP sets whether to use TCP for updates
func (c *Client) SetTCP(useTCP bool) {
	c.useTCP = useTCP
}

// SetTimeout sets the timeout for DNS operations
func (c *Client) SetTimeout(d time.Duration) {
	c.timeout = d
}

// send sends a DNS message and returns the response
func (c *Client) send(msg *dns.Msg) (*dns.Msg, error) {
	// Create a client
	client := &dns.Client{
		Net:          "tcp", // Always use TCP for updates as per spec
		ReadTimeout:  c.timeout,
		WriteTimeout: c.timeout,
	}

	// Sign the message with TSIG
	if c.tsigName != "" && c.tsigSecret != "" {
		msg.SetTsig(c.tsigName, c.tsigAlgorithm, 300, time.Now().Unix())
	}

	// Send the update
	response, _, err := client.Exchange(msg, c.server)
	if err != nil {
		return nil, fmt.Errorf("DNS update failed: %w", err)
	}

	if response == nil {
		return nil, fmt.Errorf("no response from DNS server")
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS update failed with rcode: %s (%d)",
			dns.RcodeToString[response.Rcode], response.Rcode)
	}

	return response, nil
}

// Update sends an RFC2136 update message
func (c *Client) Update(update *dns.Msg) (*dns.Msg, error) {
	return c.send(update)
}

// AddRRset adds or replaces an RRset
func (c *Client) AddRRset(zone string, rrs []dns.RR) (*dns.Msg, error) {
	update := new(dns.Msg)
	update.SetUpdate(zone)

	// First delete any existing RRset
	if len(rrs) > 0 {
		rrHeader := rrs[0].Header()
		update.RemoveRRset([]dns.RR{
			&dns.RR_Header{
				Name:   rrHeader.Name,
				Rrtype: rrHeader.Rrtype,
				Class:  dns.ClassANY,
			},
		})
	}

	// Then add the new RRs
	update.Insert(rrs)

	return c.send(update)
}

// DeleteRRset deletes an RRset
func (c *Client) DeleteRRset(zone, owner string, rrType uint16) (*dns.Msg, error) {
	update := new(dns.Msg)
	update.SetUpdate(zone)

	// Delete the RRset
	update.RemoveRRset([]dns.RR{
		&dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: rrType,
			Class:  dns.ClassANY,
		},
	})

	return c.send(update)
}

// DeleteRR deletes a specific resource record
func (c *Client) DeleteRR(zone string, rr dns.RR) (*dns.Msg, error) {
	update := new(dns.Msg)
	update.SetUpdate(zone)

	update.Remove([]dns.RR{rr})

	return c.send(update)
}

// DeleteAllRRs deletes all records at a name (RFC2136 Section 2.5.2)
func (c *Client) DeleteAllRRs(zone, owner string) (*dns.Msg, error) {
	update := new(dns.Msg)
	update.SetUpdate(zone)

	// Remove all records at the owner name
	update.Remove([]dns.RR{
		&dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: dns.TypeANY,
			Class:  dns.ClassANY,
		},
	})

	return c.send(update)
}

// Query performs a standard DNS query
func (c *Client) Query(name string, rrType uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), rrType)
	msg.RecursionDesired = false // We're querying an authoritative server

	client := &dns.Client{
		Net:         "udp", // Use UDP for queries
		ReadTimeout: c.timeout,
	}

	response, _, err := client.Exchange(msg, c.server)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	if response == nil {
		return nil, fmt.Errorf("no response from DNS server")
	}

	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("DNS query failed with rcode: %s",
			dns.RcodeToString[response.Rcode])
	}

	return response, nil
}

// BuildPTRUpdate creates an update message for adding a PTR record to a catalog zone
// This implements the idempotent catalog update from spec 10.4
func BuildPTRUpdate(catalogZone, memberZone, label string, ttl uint32) (*dns.Msg, error) {
	update := new(dns.Msg)
	update.SetUpdate(catalogZone)

	// Catalog owner name: <label>.zones.<catalog-zone>
	// Example: a1b2c3...zones.catalog.example.
	catalogOwner := fmt.Sprintf("%s.zones.%s", label, catalogZone)

	// First, delete all PTR records at this owner (for idempotency)
	update.RemoveRRset([]dns.RR{
		&dns.RR_Header{
			Name:   dns.Fqdn(catalogOwner),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassANY,
		},
	})

	// Then add the PTR record to the member zone
	ptr := &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(catalogOwner),
			Rrtype: dns.TypePTR,
			Class:  1, // ClassIN
			Ttl:    ttl,
		},
		Ptr: dns.Fqdn(memberZone),
	}

	update.Insert([]dns.RR{ptr})

	return update, nil
}

// BuildPTRDelete creates an update message for removing a PTR record from a catalog zone
func BuildPTRDelete(catalogZone, label string) (*dns.Msg, error) {
	update := new(dns.Msg)
	update.SetUpdate(catalogZone)

	// Catalog owner name: <label>.zones.<catalog-zone>
	catalogOwner := fmt.Sprintf("%s.zones.%s", label, catalogZone)

	// Delete the PTR record
	update.RemoveRRset([]dns.RR{
		&dns.RR_Header{
			Name:   dns.Fqdn(catalogOwner),
			Rrtype: dns.TypePTR,
			Class:  dns.ClassANY,
		},
	})

	return update, nil
}
