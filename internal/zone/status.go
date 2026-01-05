package zone

import (
	"fmt"

	"github.com/dlukt/dnsctl/internal/bind"
	"github.com/dlukt/dnsctl/internal/config"
	"github.com/dlukt/dnsctl/pkg/update"
	"github.com/miekg/dns"
)

// Status represents the status of a zone (spec 11.5)
type Status struct {
	Zone           string `json:"zone"`
	Exists         bool   `json:"exists"`
	Loaded         bool   `json:"loaded"`
	IsPrimary      bool   `json:"is_primary"`
	InCatalog      bool   `json:"in_catalog"`
	CatalogLabel   string `json:"catalog_label,omitempty"`
	ZoneFilePath   string `json:"zone_file_path,omitempty"`
	SOASerial      uint32 `json:"soa_serial,omitempty"`
	DNSSECEnabled  bool   `json:"dnssec_enabled"`
}

// StatusChecker handles zone status queries
type StatusChecker struct {
	cfg       *config.Config
	rndc      *bind.RNDCClient
	update    *update.Client
}

// NewStatusChecker creates a new zone status checker
func NewStatusChecker(cfg *config.Config) *StatusChecker {
	return &StatusChecker{
		cfg: cfg,
		rndc: bind.NewRNDCClient(cfg.Bind.RNDCPath, cfg.Bind.RNDCConf, cfg.Bind.View),
		update: update.NewClient(
			fmt.Sprintf("%s:%d", cfg.Bind.DNSAddr, cfg.Bind.DNSPort),
			cfg.TSIG.Name,
			cfg.TSIG.Secret,
			cfg.TSIG.Algorithm,
		),
	}
}

// ZoneStatus returns the status of a zone (spec 11.5)
func (s *StatusChecker) ZoneStatus(zoneInput string) (*Status, error) {
	// Normalize zone
	zone, err := NormalizeZone(zoneInput)
	if err != nil {
		return nil, fmt.Errorf("invalid zone name: %w", err)
	}

	status := &Status{
		Zone:         zone,
		ZoneFilePath: s.cfg.ZoneFilePath(zone),
	}

	// Check if zone exists in BIND
	exists, loaded, err := s.rndc.ZoneStatus(zone)
	if err != nil {
		return nil, fmt.Errorf("failed to check zone status: %w", err)
	}
	status.Exists = exists
	status.Loaded = loaded

	// Check if it's a primary zone
	if exists {
		isPrimary, err := s.rndc.IsZonePrimary(zone)
		if err == nil {
			status.IsPrimary = isPrimary
		}
	}

	// Check catalog membership
	label := SHA1WireLabel(zone)
	status.CatalogLabel = label

	catalogOwner := fmt.Sprintf("%s.zones.%s", label, s.cfg.Catalog.Zone)

	// Query the catalog zone for the PTR record
	response, err := s.update.Query(catalogOwner, 12) // Type PTR
	if err == nil && response != nil && len(response.Answer) > 0 {
		status.InCatalog = true
	}

	// DNSSEC is always enabled for zones created by dnsctl
	status.DNSSECEnabled = true

	// Query SOA serial if zone is loaded
	if loaded {
		response, err := s.update.Query(zone, 6) // Type SOA
		if err == nil && response != nil && len(response.Answer) > 0 {
			if soa, ok := response.Answer[0].(*dns.SOA); ok {
				status.SOASerial = soa.Serial
			}
		}
	}

	return status, nil
}
