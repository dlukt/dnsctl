package bind

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// RNDCClient provides an interface to BIND's RNDC command
type RNDCClient struct {
	rndcPath string
	rndcConf string
	view     string
	timeout  time.Duration
}

// NewRNDCClient creates a new RNDC client
func NewRNDCClient(rndcPath, rndcConf, view string) *RNDCClient {
	return &RNDCClient{
		rndcPath: rndcPath,
		rndcConf: rndcConf,
		view:     view,
		timeout:  30 * time.Second,
	}
}

// SetTimeout sets the command timeout
func (r *RNDCClient) SetTimeout(d time.Duration) {
	r.timeout = d
}

// run executes an RNDC command and returns the output
func (r *RNDCClient) run(args ...string) (string, string, error) {
	cmdArgs := []string{"-c", r.rndcConf}
	if r.view != "" {
		cmdArgs = append(cmdArgs, "-y", r.view)
	}
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command(r.rndcPath, cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the command
	if err := cmd.Start(); err != nil {
		return "", "", fmt.Errorf("failed to start rndc: %w", err)
	}

	// Wait for completion with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(r.timeout):
		_ = cmd.Process.Kill()
		return "", "", fmt.Errorf("rndc command timed out after %v", r.timeout)
	case err := <-done:
		stdoutStr := stdout.String()
		stderrStr := stderr.String()
		if err != nil {
			return stdoutStr, stderrStr, fmt.Errorf("rndc failed: %w (stderr: %s)", err, stderrStr)
		}
		return stdoutStr, stderrStr, nil
	}
}

// AddZone adds a new zone to BIND using rndc addzone
// The zoneConfig should be a BIND config block (without the outer quotes)
func (r *RNDCClient) AddZone(zone string, zoneConfig string) error {
	if zoneConfig == "" {
		return fmt.Errorf("zone config cannot be empty")
	}

	_, stderr, err := r.run("addzone", zone, zoneConfig)
	if err != nil {
		// Check for common error messages
		errMsg := stderr
		if errMsg == "" {
			errMsg = err.Error()
		}
		if strings.Contains(errMsg, "already exists") {
			return fmt.Errorf("zone already exists: %w", err)
		}
		return fmt.Errorf("failed to add zone: %w", err)
	}

	return nil
}

// DelZone removes a zone from BIND using rndc delzone
// If clean is true, uses -clean flag (removes zone file)
func (r *RNDCClient) DelZone(zone string, clean bool) error {
	args := []string{"delzone"}
	if clean {
		args = append(args, "-clean")
	}
	args = append(args, zone)

	_, stderr, err := r.run(args...)
	if err != nil {
		errMsg := stderr
		if errMsg == "" {
			errMsg = err.Error()
		}
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "no such zone") {
			return fmt.Errorf("zone not found: %w", err)
		}
		return fmt.Errorf("failed to delete zone: %w", err)
	}

	return nil
}

// ZoneStatus checks if a zone is loaded and returns its status
// Returns (exists, loaded, error)
func (r *RNDCClient) ZoneStatus(zone string) (bool, bool, error) {
	stdout, stderr, err := r.run("zonestatus", zone)
	if err != nil {
		errMsg := stderr
		if errMsg == "" {
			errMsg = err.Error()
		}
		// Zone doesn't exist
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "no such zone") {
			return false, false, nil
		}
		return false, false, fmt.Errorf("failed to get zone status: %w", err)
	}

	// Parse output to check if zone is loaded
	loaded := false
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "status:") {
			status := strings.TrimPrefix(line, "status:")
			status = strings.TrimSpace(status)
			if strings.EqualFold(status, "loaded") {
				loaded = true
			}
		}
	}

	return true, loaded, nil
}

// ShowZone displays the configuration of a zone
func (r *RNDCClient) ShowZone(zone string) (string, error) {
	stdout, stderr, err := r.run("showzone", zone)
	if err != nil {
		errMsg := stderr
		if errMsg == "" {
			errMsg = err.Error()
		}
		if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "no such zone") {
			return "", fmt.Errorf("zone not found")
		}
		return "", fmt.Errorf("failed to show zone: %w", err)
	}

	return stdout, nil
}

// Reload reloads a zone
func (r *RNDCClient) Reload(zone string) error {
	_, stderr, err := r.run("reload", zone)
	if err != nil {
		return fmt.Errorf("failed to reload zone: %w (stderr: %s)", err, stderr)
	}
	return nil
}

// Reconfig reloads the configuration
func (r *RNDCClient) Reconfig() error {
	_, stderr, err := r.run("reconfig")
	if err != nil {
		return fmt.Errorf("failed to reconfig: %w (stderr: %s)", err, stderr)
	}
	return nil
}

// Status returns the status of the BIND server
func (r *RNDCClient) Status() (string, error) {
	stdout, stderr, err := r.run("status")
	if err != nil {
		return "", fmt.Errorf("failed to get status: %w (stderr: %s)", err, stderr)
	}
	return stdout, nil
}

// ParseZoneConfig parses the zone configuration from rndc showzone output
// Returns the configuration as a map of directives
func ParseZoneConfig(output string) map[string]string {
	config := make(map[string]string)
	lines := strings.Split(output, "\n")

	inZone := false
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for zone "example.com" { pattern
		if matched, _ := regexp.MatchString(`^zone\s+["']?[\w.-]+["']?\s*\{`, line); matched {
			inZone = true
			continue
		}

		if inZone {
			if line == "}" {
				break
			}

			// Parse directives like "type primary;"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.TrimSuffix(parts[0], ";")
				value := strings.TrimSuffix(parts[1], ";")
				config[key] = value
			}
		}
	}

	return config
}

// IsZonePrimary checks if a zone is configured as a primary (master)
func (r *RNDCClient) IsZonePrimary(zone string) (bool, error) {
	output, err := r.ShowZone(zone)
	if err != nil {
		return false, err
	}

	config := ParseZoneConfig(output)
	zoneType := config["type"]
	return zoneType == "primary" || zoneType == "master", nil
}
