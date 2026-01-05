package zone

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// Normalization constants
const (
	maxDomainLength = 253 // Total domain name length (RFC 1035)
	maxLabelLength  = 63  // Single label length (RFC 1035)
)

// NormalizeZone normalizes a zone name to ASCII FQDN with trailing dot (spec 10.1)
func NormalizeZone(input string) (string, error) {
	// Trim whitespace
	input = strings.TrimSpace(input)

	// Lowercase
	input = strings.ToLower(input)

	// Convert IDN to punycode (ASCII)
	// Use strict validation for security
	profile := idna.New(
		idna.MapForLookup(),
		idna.StrictDomainName(true),
	)

	ascii, err := profile.ToASCII(input)
	if err != nil {
		return "", fmt.Errorf("invalid domain name: %w", err)
	}

	input = ascii

	// Ensure trailing dot
	if !strings.HasSuffix(input, ".") {
		input = input + "."
	}

	// Validate length
	if len(input) > maxDomainLength {
		return "", fmt.Errorf("domain name too long: %d > %d", len(input), maxDomainLength)
	}

	// Validate labels
	labels := dnsLabels(input)
	if len(labels) == 0 {
		return "", fmt.Errorf("invalid domain name: no labels")
	}

	for i, label := range labels {
		if len(label) == 0 {
			return "", fmt.Errorf("empty label at position %d", i)
		}
		if len(label) > maxLabelLength {
			return "", fmt.Errorf("label too long at position %d: %d > %d", i, len(label), maxLabelLength)
		}

		// Check for invalid characters (basic DNS label validation)
		// Labels can contain: a-z, 0-9, hyphen (but not at start/end)
		for _, ch := range label {
			if !isDNSLabelChar(ch) {
				return "", fmt.Errorf("invalid character '%c' in label at position %d", ch, i)
			}
		}

		// Label cannot start or end with hyphen
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("label at position %d cannot start or end with hyphen", i)
		}
	}

	return input, nil
}

// NormalizeOwner normalizes an owner name relative to a zone (spec 10.2)
func NormalizeOwner(input, zone string) (string, error) {
	input = strings.TrimSpace(input)

	// "@" means zone apex
	if input == "@" {
		return zone, nil
	}

	// If input is already a FQDN (ends with dot), use it as-is
	if strings.HasSuffix(input, ".") {
		// Validate it's within the zone
		if !strings.HasSuffix(strings.ToLower(input), strings.ToLower(zone)) {
			return "", fmt.Errorf("owner '%s' is not within zone '%s'", input, zone)
		}
		return strings.ToLower(input), nil
	}

	// Relative name - append zone
	fqdn := input + "." + zone
	return strings.ToLower(fqdn), nil
}

// IsWithinZone checks if an owner name is within a zone
func IsWithinZone(owner, zone string) bool {
	owner = strings.ToLower(owner)
	zone = strings.ToLower(zone)

	// Ensure both have trailing dots
	if !strings.HasSuffix(owner, ".") {
		owner = owner + "."
	}
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	return strings.HasSuffix(owner, zone)
}

// SHA1WireLabel computes the catalog member label using sha1-wire algorithm (spec 10.3)
func SHA1WireLabel(zone string) string {
	// Compute DNS wire-format of the canonical zone name
	// Wire format is: labels prefixed with length bytes + root byte (0)
	wire := dnsWireFormat(zone)

	// SHA1 digest
	hash := sha1.Sum(wire)

	// Hex-encode lowercase
	return hex.EncodeToString(hash[:])
}

// dnsWireFormat converts a domain name to DNS wire format
func dnsWireFormat(name string) []byte {
	name = strings.TrimSpace(name)

	// Ensure trailing dot
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	var buf bytes.Buffer

	// Split into labels (excluding the root)
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" {
			continue // Skip empty labels (trailing dot produces one)
		}

		// Write label length byte
		buf.WriteByte(byte(len(label)))

		// Write label bytes
		buf.WriteString(strings.ToLower(label))
	}

	// Write root byte (terminator)
	buf.WriteByte(0)

	return buf.Bytes()
}

// dnsLabels splits a domain name into labels
func dnsLabels(name string) []string {
	name = strings.TrimSpace(name)

	// Remove trailing dot
	if strings.HasSuffix(name, ".") {
		name = name[:len(name)-1]
	}

	if name == "" {
		return []string{}
	}

	return strings.Split(name, ".")
}

// isDNSLabelChar checks if a character is valid in a DNS label
func isDNSLabelChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '-'
}

// ValidateRecordType checks if a record type is valid
func ValidateRecordType(rrType string) bool {
	validTypes := map[string]bool{
		"A":     true,
		"AAAA":  true,
		"CNAME": true,
		"TXT":   true,
		"MX":    true,
		"SRV":   true,
		"CAA":   true,
		"NS":    true,
		"SOA":   true,
		"PTR":   true,
	}
	return validTypes[strings.ToUpper(rrType)]
}

// IsApexOwner checks if an owner is at the zone apex
func IsApexOwner(owner, zone string) bool {
	owner = strings.ToLower(owner)
	zone = strings.ToLower(zone)

	// Normalize both to FQDN with trailing dot
	if !strings.HasSuffix(owner, ".") {
		owner = owner + "."
	}
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	return owner == zone
}
