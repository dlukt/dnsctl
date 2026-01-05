package zone

import (
	"fmt"
	"strings"

	"github.com/dlukt/dnsctl/internal/bind"
	"github.com/dlukt/dnsctl/internal/config"
	"github.com/dlukt/dnsctl/internal/lock"
	"github.com/dlukt/dnsctl/pkg/update"
)

// Creator handles zone creation operations
type Creator struct {
	cfg       *config.Config
	rndc      *bind.RNDCClient
	update    *update.Client
}

// NewCreator creates a new zone creator
func NewCreator(cfg *config.Config) *Creator {
	return &Creator{
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

// CreateZone creates a new authoritative primary zone (spec 11.1)
func (c *Creator) CreateZone(zoneInput string, changes *[]string) error {
	// Step 1: Normalize and validate zone
	zone, err := NormalizeZone(zoneInput)
	if err != nil {
		return fmt.Errorf("invalid zone name: %w", err)
	}

	// Step 2: Acquire zone lock
	zoneLock := lock.New(c.cfg.LockFilePath(zone))
	if err := zoneLock.Acquire(); err != nil {
		return fmt.Errorf("failed to acquire zone lock: %w", err)
	}
	defer zoneLock.Release()

	// Step 3: Ensure zones directory exists
	if err := c.cfg.EnsureDirs(); err != nil {
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	// Step 4: Determine zone file path
	zoneFilePath := c.cfg.ZoneFilePath(zone)

	// Step 5: Check if zone already exists
	exists, _, err := c.rndc.ZoneStatus(zone)
	if err == nil && exists {
		// Zone exists, ensure catalog membership
		*changes = append(*changes, "zone_already_exists")
		return c.ensureCatalogMembership(zone, changes)
	}

	// Step 6: Create stub zone file
	zoneData := DefaultZoneFileData(zone)
	if err := WriteZoneFile(zoneFilePath, zoneData, c.cfg.Zones.FileOwner, c.cfg.Zones.FileGroup); err != nil {
		return fmt.Errorf("failed to write zone file: %w", err)
	}
	*changes = append(*changes, "zone_file_created")

	// Step 7: Build RNDC addzone config stanza
	zoneConfig := c.buildZoneConfig(zoneFilePath)

	// Step 8: Execute rndc addzone
	if err := c.rndc.AddZone(zone, zoneConfig); err != nil {
		// Clean up zone file on failure
		_ = RemoveZoneFile(zoneFilePath)
		return fmt.Errorf("failed to add zone via RNDC: %w", err)
	}
	*changes = append(*changes, "zone_added")

	// Step 9: Add to catalog zone
	if err := c.ensureCatalogMembership(zone, changes); err != nil {
		// Attempt to roll back
		_ = c.rndc.DelZone(zone, true)
		_ = RemoveZoneFile(zoneFilePath)
		return fmt.Errorf("failed to update catalog zone: %w", err)
	}

	return nil
}

// buildZoneConfig builds the RNDC addzone configuration stanza (spec 11.1, step 7)
func (c *Creator) buildZoneConfig(zoneFilePath string) string {
	var config strings.Builder

	config.WriteString("type primary;\n")
	config.WriteString(fmt.Sprintf("file \"%s\";\n", zoneFilePath))
	config.WriteString(fmt.Sprintf("notify %s;\n", boolToYesNo(c.cfg.Zones.DefaultNotify)))
	config.WriteString(fmt.Sprintf("dnssec-policy %s;\n", c.cfg.Zones.DNSSECPolicy))
	config.WriteString("inline-signing yes;\n")

	// Add update permissions based on mode
	if c.cfg.Zones.UpdateMode == "allow-update" {
		config.WriteString(fmt.Sprintf("allow-update { key \"%s\"; };\n", c.cfg.Zones.TSIGKeyName))
	} else {
		// update-policy mode
		config.WriteString(fmt.Sprintf("update-policy { grant %s %s; };\n",
			c.cfg.Zones.TSIGKeyName, c.cfg.Zones.UpdatePolicyGrant))
	}

	return config.String()
}

// ensureCatalogMembership ensures the zone is in the catalog zone (spec 11.3)
func (c *Creator) ensureCatalogMembership(zone string, changes *[]string) error {
	// Compute catalog member label
	label := SHA1WireLabel(zone)

	// Build the catalog update message
	updateMsg, err := update.BuildPTRUpdate(
		c.cfg.Catalog.Zone,
		zone,
		label,
		60, // Catalog TTL
	)
	if err != nil {
		return fmt.Errorf("failed to build catalog update: %w", err)
	}

	// Send the update
	if _, err := c.update.Update(updateMsg); err != nil {
		return fmt.Errorf("failed to send catalog update: %w", err)
	}

	*changes = append(*changes, "catalog_updated")
	return nil
}

// boolToYesNo converts a boolean to "yes" or "no" for BIND config
func boolToYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
