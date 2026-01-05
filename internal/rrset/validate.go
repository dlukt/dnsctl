package rrset

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/dlukt/dnsctl/internal/config"
	zonepkg "github.com/dlukt/dnsctl/internal/zone"
	"github.com/miekg/dns"
)

// Validator validates RRset updates
type Validator struct {
	cfg *config.Config
}

// NewValidator creates a new RRset validator
func NewValidator(cfg *config.Config) *Validator {
	return &Validator{cfg: cfg}
}

// ValidateRDATA validates resource data for a given record type (spec 12.1, 12.5)
func (v *Validator) ValidateRDATA(rrType string, rdata []string) error {
	rrType = strings.ToUpper(rrType)

	// Check if type is allowed
	if !v.cfg.IsAllowedRRType(rrType) {
		return fmt.Errorf("RR type %s is not allowed", rrType)
	}

	switch rrType {
	case "A":
		return v.validateA(rdata)
	case "AAAA":
		return v.validateAAAA(rdata)
	case "CNAME":
		return v.validateCNAME(rdata)
	case "TXT":
		return v.validateTXT(rdata)
	case "MX":
		return v.validateMX(rdata)
	case "SRV":
		return v.validateSRV(rdata)
	case "CAA":
		return v.validateCAA(rdata)
	case "NS":
		return v.validateNS(rdata)
	default:
		// For unknown types, just check that rdata is provided
		if len(rdata) == 0 {
			return fmt.Errorf("no rdata provided")
		}
	}

	return nil
}

// validateA validates A record data
func (v *Validator) validateA(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no IP address provided")
	}
	for _, ip := range rdata {
		if net.ParseIP(ip) == nil || strings.Contains(ip, ":") {
			return fmt.Errorf("invalid IPv4 address: %s", ip)
		}
	}
	return nil
}

// validateAAAA validates AAAA record data
func (v *Validator) validateAAAA(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no IP address provided")
	}
	for _, ip := range rdata {
		parsed := net.ParseIP(ip)
		if parsed == nil || !strings.Contains(ip, ":") {
			return fmt.Errorf("invalid IPv6 address: %s", ip)
		}
	}
	return nil
}

// validateCNAME validates CNAME record data
func (v *Validator) validateCNAME(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no target provided")
	}
	target := strings.TrimSpace(rdata[0])

	// Basic domain validation - more thorough validation can be added
	if target == "" {
		return fmt.Errorf("CNAME target cannot be empty")
	}

	// CNAME should not point to another CNAME (we can't check this here without a query)
	return nil
}

// validateTXT validates TXT record data
func (v *Validator) validateTXT(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no text provided")
	}
	// TXT records can contain any text
	return nil
}

// validateMX validates MX record data
func (v *Validator) validateMX(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no MX data provided")
	}

	for _, mx := range rdata {
		parts := strings.Fields(mx)
		if len(parts) != 2 {
			return fmt.Errorf("MX record must be: preference host, got: %s", mx)
		}

		// Validate preference
		pref := parts[0]
		if _, err := strconv.ParseUint(pref, 10, 16); err != nil {
			return fmt.Errorf("invalid MX preference: %s", pref)
		}

		// Validate host
		host := parts[1]
		if host == "" {
			return fmt.Errorf("MX host cannot be empty")
		}
	}

	return nil
}

// validateSRV validates SRV record data
func (v *Validator) validateSRV(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no SRV data provided")
	}

	for _, srv := range rdata {
		parts := strings.Fields(srv)
		if len(parts) != 4 {
			return fmt.Errorf("SRV record must be: priority weight port target, got: %s", srv)
		}

		// Validate priority
		if _, err := strconv.ParseUint(parts[0], 10, 16); err != nil {
			return fmt.Errorf("invalid SRV priority: %s", parts[0])
		}

		// Validate weight
		if _, err := strconv.ParseUint(parts[1], 10, 16); err != nil {
			return fmt.Errorf("invalid SRV weight: %s", parts[1])
		}

		// Validate port
		if _, err := strconv.ParseUint(parts[2], 10, 16); err != nil {
			return fmt.Errorf("invalid SRV port: %s", parts[2])
		}

		// Validate target
		target := parts[3]
		if target == "" {
			return fmt.Errorf("SRV target cannot be empty")
		}
	}

	return nil
}

// validateCAA validates CAA record data
func (v *Validator) validateCAA(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no CAA data provided")
	}

	for _, caa := range rdata {
		parts := strings.Fields(caa)
		if len(parts) < 3 {
			return fmt.Errorf("CAA record must be: flags tag value, got: %s", caa)
		}

		// Validate flags (should be 0 or 1)
		flags := parts[0]
		if flags != "0" && flags != "1" {
			return fmt.Errorf("CAA flags must be 0 or 1, got: %s", flags)
		}

		// Validate tag
		tag := parts[1]
		if tag != "issue" && tag != "issuewild" && tag != "iodef" {
			return fmt.Errorf("CAA tag must be issue, issuewild, or iodef, got: %s", tag)
		}
	}

	return nil
}

// validateNS validates NS record data
func (v *Validator) validateNS(rdata []string) error {
	if len(rdata) == 0 {
		return fmt.Errorf("no nameserver provided")
	}
	for _, ns := range rdata {
		if strings.TrimSpace(ns) == "" {
			return fmt.Errorf("NS record cannot be empty")
		}
	}
	return nil
}

// ValidatePolicy checks policy enforcement rules (spec 12.1)
func (v *Validator) ValidatePolicy(zone, owner, rrType string) error {
	// Check apex CNAME policy (spec 15.2)
	if v.cfg.Policy.DisallowApexCNAME && strings.ToUpper(rrType) == "CNAME" {
		if zonepkg.IsApexOwner(owner, zone) {
			return fmt.Errorf("CNAME at zone apex is not allowed")
		}
	}

	// Check NS updates policy (spec 15.3)
	if v.cfg.Policy.DisallowNSUpdates && strings.ToUpper(rrType) == "NS" {
		return fmt.Errorf("NS record updates are not allowed")
	}

	return nil
}

// BuildRR builds a DNS resource record from components
func BuildRR(owner, rrType string, ttl uint32, rdata string) (dns.RR, error) {
	owner = dns.Fqdn(owner)
	rrType = strings.ToUpper(rrType)

	var rr dns.RR

	switch rrType {
	case "A":
		rr = &dns.A{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeA,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			A: net.ParseIP(rdata),
		}
	case "AAAA":
		rr = &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeAAAA,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			AAAA: net.ParseIP(rdata),
		}
	case "CNAME":
		rr = &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeCNAME,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			Target: dns.Fqdn(rdata),
		}
	case "TXT":
		rr = &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeTXT,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			Txt: splitTXT(rdata),
		}
	case "MX":
		parts := strings.Fields(rdata)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid MX format")
		}
		pref64, _ := strconv.ParseUint(parts[0], 10, 16)
		pref := uint16(pref64)
		rr = &dns.MX{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeMX,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			Preference: pref,
			Mx:         dns.Fqdn(parts[1]),
		}
	case "SRV":
		parts := strings.Fields(rdata)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid SRV format")
		}
		priority64, _ := strconv.ParseUint(parts[0], 10, 16)
		weight64, _ := strconv.ParseUint(parts[1], 10, 16)
		port64, _ := strconv.ParseUint(parts[2], 10, 16)
		rr = &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeSRV,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			Priority: uint16(priority64),
			Weight:   uint16(weight64),
			Port:     uint16(port64),
			Target:   dns.Fqdn(parts[3]),
		}
	case "CAA":
		parts := strings.Fields(rdata)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid CAA format")
		}
		flag64, _ := strconv.ParseUint(parts[0], 10, 8)
		tag := parts[1]
		value := strings.Join(parts[2:], " ")
		rr = &dns.CAA{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeCAA,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			Flag:  uint8(flag64),
			Tag:   tag,
			Value: value,
		}
	case "NS":
		rr = &dns.NS{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNS,
				Class:  1, // ClassIN
				Ttl:    ttl,
			},
			Ns: dns.Fqdn(rdata),
		}
	default:
		return nil, fmt.Errorf("unsupported RR type: %s", rrType)
	}

	return rr, nil
}

// splitTXT splits TXT record data into chunks (255 bytes max per chunk)
func splitTXT(txt string) []string {
	// For simplicity, just return the whole string as one chunk
	// A proper implementation would split into 255-byte chunks
	return []string{txt}
}
