package rrset

import (
	"fmt"

	"github.com/dlukt/dnsctl/internal/config"
	"github.com/dlukt/dnsctl/internal/lock"
	"github.com/dlukt/dnsctl/internal/zone"
	"github.com/dlukt/dnsctl/pkg/update"
	"github.com/miekg/dns"
)

// UpsertResult contains the result of an RRset upsert operation
type UpsertResult struct {
	Success bool     `json:"success"`
	Owner   string   `json:"owner"`
	Type    string   `json:"type"`
	TTL     uint32   `json:"ttl"`
	RData   []string `json:"rdata"`
}

// Manager handles RRset upsert operations (spec 12.2)
type Manager struct {
	cfg    *config.Config
	update *update.Client
}

// NewManager creates a new RRset manager
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg: cfg,
		update: update.NewClient(
			fmt.Sprintf("%s:%d", cfg.Bind.DNSAddr, cfg.Bind.DNSPort),
			cfg.TSIG.Name,
			cfg.TSIG.Secret,
			cfg.TSIG.Algorithm,
		),
	}
}

// Upsert replaces an entire RRset at (owner, type) with the provided values (spec 12.2)
func (m *Manager) Upsert(zoneInput, ownerInput, rrType string, ttl uint32, rdata []string) (*UpsertResult, error) {
	// Normalize inputs
	zoneFQDN, err := zone.NormalizeZone(zoneInput)
	if err != nil {
		return nil, fmt.Errorf("invalid zone: %w", err)
	}

	owner, err := zone.NormalizeOwner(ownerInput, zoneFQDN)
	if err != nil {
		return nil, fmt.Errorf("invalid owner: %w", err)
	}

	// Validate TTL
	if err := m.cfg.ValidateTTL(ttl); err != nil {
		return nil, fmt.Errorf("invalid TTL: %w", err)
	}

	// Validate RR type
	rrTypeUpper := dns.TypeToString[dns.StringToType[rrType]]
	if rrTypeUpper == "" {
		rrTypeUpper = rrType
	}
	if !m.cfg.IsAllowedRRType(rrTypeUpper) {
		return nil, fmt.Errorf("RR type %s is not allowed", rrTypeUpper)
	}

	// Create validator
	validator := NewValidator(m.cfg)

	// Validate RDATA
	if err := validator.ValidateRDATA(rrTypeUpper, rdata); err != nil {
		return nil, fmt.Errorf("invalid RDATA: %w", err)
	}

	// Validate policy
	if err := validator.ValidatePolicy(zoneFQDN, owner, rrTypeUpper); err != nil {
		return nil, fmt.Errorf("policy violation: %w", err)
	}

	// Acquire zone lock (recommended per spec 12.2)
	zoneLock := lock.New(m.cfg.LockFilePath(zoneFQDN))
	if err := zoneLock.Acquire(); err != nil {
		return nil, fmt.Errorf("failed to acquire zone lock: %w", err)
	}
	defer zoneLock.Release()

	// Build resource records
	var rrs []dns.RR
	for _, rd := range rdata {
		rr, err := BuildRR(owner, rrTypeUpper, ttl, rd)
		if err != nil {
			return nil, fmt.Errorf("failed to build RR: %w", err)
		}
		rrs = append(rrs, rr)
	}

	// Send the update (spec 12.2, step 3: delete RRset + add new RRset)
	if _, err := m.update.AddRRset(zoneFQDN, rrs); err != nil {
		return nil, fmt.Errorf("failed to send update: %w", err)
	}

	// Optional read-after-write verification (spec 12.2, step 4)
	// This is optional - can be enabled via config flag later

	return &UpsertResult{
		Success: true,
		Owner:   owner,
		Type:    rrTypeUpper,
		TTL:     ttl,
		RData:   rdata,
	}, nil
}
