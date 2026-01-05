package zone

import (
	"fmt"

	"github.com/dlukt/dnsctl/internal/bind"
	"github.com/dlukt/dnsctl/internal/config"
	"github.com/dlukt/dnsctl/internal/lock"
	"github.com/dlukt/dnsctl/pkg/update"
)

// Deleter handles zone deletion operations
type Deleter struct {
	cfg       *config.Config
	rndc      *bind.RNDCClient
	update    *update.Client
}

// NewDeleter creates a new zone deleter
func NewDeleter(cfg *config.Config) *Deleter {
	return &Deleter{
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

// DeleteZone removes a zone (spec 11.4)
func (d *Deleter) DeleteZone(zoneInput string, changes *[]string) error {
	// Step 1: Normalize zone
	zone, err := NormalizeZone(zoneInput)
	if err != nil {
		return fmt.Errorf("invalid zone name: %w", err)
	}

	// Step 2: Acquire zone lock
	zoneLock := lock.New(d.cfg.LockFilePath(zone))
	if err := zoneLock.Acquire(); err != nil {
		return fmt.Errorf("failed to acquire zone lock: %w", err)
	}
	defer zoneLock.Release()

	// Step 3: Remove from catalog zone (spec 11.4, step 3)
	if err := d.removeFromCatalog(zone, changes); err != nil {
		return fmt.Errorf("failed to remove from catalog: %w", err)
	}

	// Step 4: Delete zone from BIND (spec 11.4, step 4)
	if err := d.rndc.DelZone(zone, true); err != nil {
		return fmt.Errorf("failed to delete zone via RNDC: %w", err)
	}
	*changes = append(*changes, "zone_deleted")

	// Step 5: Remove zone file (best-effort, spec 11.4, step 5)
	zoneFilePath := d.cfg.ZoneFilePath(zone)
	if err := RemoveZoneFile(zoneFilePath); err != nil {
		// Log warning but don't fail - this is best-effort
		*changes = append(*changes, "zone_file_cleanup_failed")
	} else {
		*changes = append(*changes, "zone_file_removed")
	}

	return nil
}

// removeFromCatalog removes the zone from the catalog zone (spec 11.4, step 3)
func (d *Deleter) removeFromCatalog(zone string, changes *[]string) error {
	// Compute catalog member label
	label := SHA1WireLabel(zone)

	// Build the catalog delete message
	updateMsg, err := update.BuildPTRDelete(d.cfg.Catalog.Zone, label)
	if err != nil {
		return fmt.Errorf("failed to build catalog delete: %w", err)
	}

	// Send the update
	if _, err := d.update.Update(updateMsg); err != nil {
		return fmt.Errorf("failed to send catalog delete: %w", err)
	}

	*changes = append(*changes, "catalog_updated")
	return nil
}
