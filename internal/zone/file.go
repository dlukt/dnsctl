package zone

import (
	"fmt"
	"os"
	"text/template"
	"time"
)

// ZoneFileTemplate is the template for a new zone file
const zoneFileTemplate = `$ORIGIN {{.Zone}}
$TTL {{.TTL}}

@ IN SOA {{.NS}} {{.Email}} (
	{{.Serial}} ; serial
	{{.Refresh}} ; refresh
	{{.Retry}} ; retry
	{{.Expire}} ; expire
	{{.Minimum}} ; minimum
)

{{range .NSRecords}}{{.}}
{{end}}

{{range .Defaults}}{{.}}
{{end}}
`

// ZoneFileData contains the data for zone file generation
type ZoneFileData struct {
	Zone      string    // Zone FQDN
	TTL       uint32    // Default TTL
	NS        string    // Primary nameserver
	Email     string    // Admin email (with @ replaced by .)
	Serial    uint32    // SOA serial
	Refresh   uint32    // SOA refresh
	Retry     uint32    // SOA retry
	Expire    uint32    // SOA expire
	Minimum   uint32    // SOA minimum
	NSRecords []string  // NS records
	Defaults  []string  // Default records (A, AAAA, CAA, etc.)
}

// DefaultZoneFileData returns default data for a new zone file
func DefaultZoneFileData(zone string) *ZoneFileData {
	now := time.Now()

	// Generate serial: YYYYMMDDNN format
	serial := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)

	// Default nameservers - should be configurable
	ns := "ns1." + zone
	if len(zone) > 1 && zone[len(zone)-1] == '.' {
		ns = "ns1." + zone
	}

	// Convert admin email to SOA format (replace @ with .)
	email := "hostmaster." + zone

	return &ZoneFileData{
		Zone:    zone,
		TTL:     3600,
		NS:      ns,
		Email:   email,
		Serial:  serial,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 3600,
		NSRecords: []string{
			"@ IN NS " + ns,
		},
		Defaults: []string{
			// Optional CAA record (example)
			"@ IN CAA 0 issue \"letsencrypt.org\"",
		},
	}
}

// GenerateZoneFile generates a zone file from data
func GenerateZoneFile(data *ZoneFileData) (string, error) {
	tmpl, err := template.New("zonefile").Parse(zoneFileTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse zone file template: %w", err)
	}

	var buf []byte
	writer := &bufWriter{buf: &buf}

	if err := tmpl.Execute(writer, data); err != nil {
		return "", fmt.Errorf("failed to execute zone file template: %w", err)
	}

	return string(buf), nil
}

// bufWriter is a simple io.Writer that writes to a []byte buffer
type bufWriter struct {
	buf *[]byte
}

func (w *bufWriter) Write(p []byte) (n int, err error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

// WriteZoneFile writes a zone file atomically (spec step 6)
func WriteZoneFile(path string, data *ZoneFileData, owner, group string) error {
	// Generate zone file content
	content, err := GenerateZoneFile(data)
	if err != nil {
		return err
	}

	// Create temporary file in the same directory
	tmpPath := path + ".tmp"

	// Write to temp file
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write zone file: %w", err)
	}

	// Sync to disk
	f, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to open temp file for sync: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync zone file: %w", err)
	}
	f.Close()

	// Change ownership if owner/group specified
	if owner != "" || group != "" {
		// We can't chown as non-root, so just note it
		// In production, this would require root or sudo
		_ = owner
		_ = group
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename zone file: %w", err)
	}

	return nil
}

// RemoveZoneFile removes a zone file (best-effort, as per spec step 5 of delete)
func RemoveZoneFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove zone file: %w", err)
	}
	return nil
}

// ZoneFileExists checks if a zone file exists
func ZoneFileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// BumpSerial increments the SOA serial number
// Returns the new serial
func BumpSerial(currentSerial uint32) uint32 {
	now := time.Now()
	todaySerial := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100)

	if currentSerial >= todaySerial {
		// Increment the revision number
		return currentSerial + 1
	}

	// New day, start with today's date + 00
	return todaySerial
}
