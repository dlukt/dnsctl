// Package acme provides ACME DNS-01 challenge handling for automated certificate issuance.
package acme

import (
	"fmt"

	"github.com/dlukt/dnsctl/internal/config"
	"github.com/dlukt/dnsctl/internal/rrset"
	"github.com/dlukt/dnsctl/internal/zone"
)

// ACMEHandler handles ACME DNS-01 challenges (spec 12.6)
type ACMEHandler struct {
	cfg     *config.Config
	manager *rrset.Manager
}

// NewACMEHandler creates a new ACME handler
func NewACMEHandler(cfg *config.Config) *ACMEHandler {
	return &ACMEHandler{
		cfg:     cfg,
		manager: rrset.NewManager(cfg),
	}
}

// Present creates a TXT record for the ACME DNS-01 challenge (spec 12.6)
// Equivalent to: rrset upsert <zone> _acme-challenge.<fqdn> TXT <value>
func (h *ACMEHandler) Present(zoneInput, fqdn, value string, ttl uint32) (*rrset.UpsertResult, error) {
	// Normalize zone
	zoneFQDN, err := zone.NormalizeZone(zoneInput)
	if err != nil {
		return nil, fmt.Errorf("invalid zone: %w", err)
	}

	// Build the ACME challenge owner
	// The fqdn should be within the zone
	owner, err := zone.NormalizeOwner(fqdn, zoneFQDN)
	if err != nil {
		return nil, fmt.Errorf("invalid FQDN: %w", err)
	}

	// Prepend _acme-challenge if not already present
	if len(owner) > 16 && !containsPrefix(owner, "_acme-challenge.") {
		// Extract the base owner (remove zone suffix)
		// and prepend _acme-challenge.
		baseOwner := owner
		if len(owner) > len(zoneFQDN) && owner[len(owner)-len(zoneFQDN):] == zoneFQDN {
			baseOwner = owner[:len(owner)-len(zoneFQDN)]
			if baseOwner[len(baseOwner)-1] == '.' {
				baseOwner = baseOwner[:len(baseOwner)-1]
			}
		}
		owner = "_acme-challenge." + baseOwner + "." + zoneFQDN
	}

	// Use default TTL if not specified
	if ttl == 0 {
		ttl = 60
	}

	// Create the TXT record
	// For ACME multi-value semantics (spec 12.6), we could implement
	// append-only behavior, but for simplicity we use replace
	result, err := h.manager.Upsert(zoneFQDN, owner, "TXT", ttl, []string{value})
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME challenge record: %w", err)
	}

	return result, nil
}

// Cleanup removes the TXT record for the ACME DNS-01 challenge (spec 12.6)
// Equivalent to: rrset delete <zone> _acme-challenge.<fqdn> TXT
func (h *ACMEHandler) Cleanup(zoneInput, fqdn, value string) error {
	// Normalize zone
	zoneFQDN, err := zone.NormalizeZone(zoneInput)
	if err != nil {
		return fmt.Errorf("invalid zone: %w", err)
	}

	// Build the ACME challenge owner
	owner, err := zone.NormalizeOwner(fqdn, zoneFQDN)
	if err != nil {
		return fmt.Errorf("invalid FQDN: %w", err)
	}

	// Prepend _acme-challenge if not already present
	if len(owner) > 16 && !containsPrefix(owner, "_acme-challenge.") {
		baseOwner := owner
		if len(owner) > len(zoneFQDN) && owner[len(owner)-len(zoneFQDN):] == zoneFQDN {
			baseOwner = owner[:len(owner)-len(zoneFQDN)]
			if baseOwner[len(baseOwner)-1] == '.' {
				baseOwner = baseOwner[:len(baseOwner)-1]
			}
		}
		owner = "_acme-challenge." + baseOwner + "." + zoneFQDN
	}

	// Delete the TXT record
	_, err = h.manager.Delete(zoneFQDN, owner, "TXT")
	if err != nil {
		return fmt.Errorf("failed to remove ACME challenge record: %w", err)
	}

	return nil
}

// containsPrefix checks if a string starts with a prefix (case-insensitive for domain names)
func containsPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	// Case-insensitive compare for domain names
	for i := 0; i < len(prefix); i++ {
		sc := s[i]
		pc := prefix[i]

		// Convert to lowercase for comparison
		if sc >= 'A' && sc <= 'Z' {
			sc += 32
		}
		if pc >= 'A' && pc <= 'Z' {
			pc += 32
		}

		if sc != pc {
			return false
		}
	}
	return true
}
