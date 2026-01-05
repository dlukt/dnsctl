package rrset

import (
	"fmt"

	"github.com/dlukt/dnsctl/internal/lock"
	"github.com/dlukt/dnsctl/internal/zone"
	"github.com/miekg/dns"
)

// DeleteResult contains the result of an RRset delete operation
type DeleteResult struct {
	Success bool   `json:"success"`
	Owner   string `json:"owner"`
	Type    string `json:"type"`
}

// Delete removes an RRset at (owner, type) (spec 12.3)
func (m *Manager) Delete(zoneInput, ownerInput, rrType string) (*DeleteResult, error) {
	// Normalize inputs
	zoneFQDN, err := zone.NormalizeZone(zoneInput)
	if err != nil {
		return nil, fmt.Errorf("invalid zone: %w", err)
	}

	owner, err := zone.NormalizeOwner(ownerInput, zoneFQDN)
	if err != nil {
		return nil, fmt.Errorf("invalid owner: %w", err)
	}

	// Validate RR type
	rrTypeUpper := rrType
	if typeNum := dns.StringToType[rrType]; typeNum != 0 {
		rrTypeUpper = dns.TypeToString[typeNum]
	}
	if !m.cfg.IsAllowedRRType(rrTypeUpper) {
		return nil, fmt.Errorf("RR type %s is not allowed", rrTypeUpper)
	}

	// Validate policy
	validator := NewValidator(m.cfg)
	if err := validator.ValidatePolicy(zoneFQDN, owner, rrTypeUpper); err != nil {
		return nil, fmt.Errorf("policy violation: %w", err)
	}

	// Acquire zone lock
	zoneLock := lock.New(m.cfg.LockFilePath(zoneFQDN))
	if err := zoneLock.Acquire(); err != nil {
		return nil, fmt.Errorf("failed to acquire zone lock: %w", err)
	}
	defer zoneLock.Release()

	// Send the delete update
	typeNum := dns.StringToType[rrTypeUpper]
	if _, err := m.update.DeleteRRset(zoneFQDN, owner, typeNum); err != nil {
		return nil, fmt.Errorf("failed to send delete update: %w", err)
	}

	return &DeleteResult{
		Success: true,
		Owner:   owner,
		Type:    rrTypeUpper,
	}, nil
}
