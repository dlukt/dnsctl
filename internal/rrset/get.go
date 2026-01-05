package rrset

import (
	"fmt"
	"strings"

	"github.com/dlukt/dnsctl/internal/zone"
	"github.com/dlukt/dnsctl/pkg/update"
	"github.com/miekg/dns"
)

// Ensure update package is used - this is a workaround for Go's per-file import checking
// The Manager type (defined in upsert.go) has an update field that we use via m.update.Query
func init() {
	// This references the update package to satisfy the import checker
	var _ update.Client
}

// GetResult contains the result of an RRset query (spec 12.4)
type GetResult struct {
	Found  bool     `json:"found"`
	Owner  string   `json:"owner"`
	Type   string   `json:"type"`
	TTL    uint32   `json:"ttl"`
	RData  []string `json:"rdata"`
}

// Get retrieves an RRset at (owner, type) (spec 12.4)
func (m *Manager) Get(zoneInput, ownerInput, rrType string) (*GetResult, error) {
	// Normalize inputs
	zoneFQDN, err := zone.NormalizeZone(zoneInput)
	if err != nil {
		return nil, fmt.Errorf("invalid zone: %w", err)
	}

	owner, err := zone.NormalizeOwner(ownerInput, zoneFQDN)
	if err != nil {
		return nil, fmt.Errorf("invalid owner: %w", err)
	}

	// Normalize RR type
	rrTypeUpper := strings.ToUpper(rrType)
	typeNum := dns.StringToType[rrTypeUpper]
	if typeNum == 0 {
		return nil, fmt.Errorf("unknown RR type: %s", rrTypeUpper)
	}

	// Perform standard DNS query against local named (spec 12.4)
	response, err := m.update.Query(owner, typeNum)
	if err != nil {
		return nil, fmt.Errorf("DNS query failed: %w", err)
	}

	// Check if we got any answers
	if len(response.Answer) == 0 {
		// NXDOMAIN or NOERROR with no records
		return &GetResult{
			Found: false,
			Owner: owner,
			Type:  rrTypeUpper,
		}, nil
	}

	// Filter answers for the correct type and owner
	var matchingRRs []dns.RR
	for _, rr := range response.Answer {
		if rr.Header().Rrtype == typeNum && strings.EqualFold(rr.Header().Name, owner) {
			matchingRRs = append(matchingRRs, rr)
		}
	}

	if len(matchingRRs) == 0 {
		return &GetResult{
			Found: false,
			Owner: owner,
			Type:  rrTypeUpper,
		}, nil
	}

	// Extract RDATA from matching RRs
	var rdata []string
	ttl := matchingRRs[0].Header().Ttl

	for _, rr := range matchingRRs {
		switch v := rr.(type) {
		case *dns.A:
			rdata = append(rdata, v.A.String())
		case *dns.AAAA:
			rdata = append(rdata, v.AAAA.String())
		case *dns.CNAME:
			rdata = append(rdata, v.Target)
		case *dns.TXT:
			rdata = append(rdata, strings.Join(v.Txt, " "))
		case *dns.MX:
			rdata = append(rdata, fmt.Sprintf("%d %s", v.Preference, v.Mx))
		case *dns.SRV:
			rdata = append(rdata, fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target))
		case *dns.CAA:
			rdata = append(rdata, fmt.Sprintf("%d %s %s", v.Flag, v.Tag, v.Value))
		case *dns.NS:
			rdata = append(rdata, v.Ns)
		case *dns.PTR:
			rdata = append(rdata, v.Ptr)
		}
	}

	return &GetResult{
		Found: true,
		Owner: owner,
		Type:  rrTypeUpper,
		TTL:   ttl,
		RData: rdata,
	}, nil
}
