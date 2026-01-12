// Package ssh provides SSH forced-command mode support for secure remote dnsctl access.
package ssh

import (
	"fmt"
	"os"
	"strings"

	"github.com/dlukt/dnsctl/internal/audit"
)

// WrapHandler handles SSH forced-command mode (--ssh-wrap)
type WrapHandler struct {
	logger *audit.Logger
}

// NewWrapHandler creates a new SSH wrap handler
func NewWrapHandler(logger *audit.Logger) *WrapHandler {
	return &WrapHandler{
		logger: logger,
	}
}

// Allowed subcommands for SSH wrap mode
var allowedSubcommands = map[string]bool{
	"doctor": true,
	"version": true,
	"zone": true,
	"rrset": true,
	"acme": true,
}

// Allowed flags for each subcommand
var allowedFlags = map[string]map[string]bool{
	"zone": {
		"create": true,
		"delete": true,
		"status": true,
		"list": true,
		"limit": true,
	},
	"rrset": {
		"upsert": true,
		"delete": true,
		"get": true,
		"ttl": true,
	},
	"acme": {
		"present": true,
		"cleanup": true,
		"ttl": true,
	},
}

// Handle wraps the SSH command execution (spec 8.1, 17)
func (h *WrapHandler) Handle() error {
	// Get the original command from SSH environment
	originalCmd := os.Getenv("SSH_ORIGINAL_COMMAND")
	if originalCmd == "" {
		return fmt.Errorf("no SSH_ORIGINAL_COMMAND found")
	}

	// Extract actor identity
	actor := os.Getenv("USER")
	// Could also map SSH key comment to actor here

	h.logger.WithActor(actor)

	// Parse the command
	parts := strings.Fields(originalCmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	// Validate subcommand
	subcommand := parts[0]
	if !allowedSubcommands[subcommand] {
		return fmt.Errorf("subcommand '%s' is not allowed", subcommand)
	}

	// Validate flags based on subcommand
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if strings.HasPrefix(part, "-") {
			flagName := strings.TrimPrefix(part, "-")
			flagName = strings.TrimPrefix(flagName, "-")

			// Check if flag is allowed for this subcommand
			if allowed, ok := allowedFlags[subcommand]; ok {
				if !allowed[flagName] {
					return fmt.Errorf("flag '%s' is not allowed for subcommand '%s'", flagName, subcommand)
				}
			}
		}
	}

	// Log the wrapped command
	h.logger.Info(fmt.Sprintf("SSH wrapped command: %s", originalCmd))

	// Execute the validated command
	// In a real implementation, this would dispatch to the actual command handler
	// For now, we just return success
	return nil
}

// ParseCommand parses a command string into components
func ParseCommand(cmd string) ([]string, error) {
	if cmd == "" {
		return nil, fmt.Errorf("empty command")
	}

	// Simple parsing - split on whitespace
	// A more robust implementation would handle quoted strings
	parts := strings.Fields(cmd)
	return parts, nil
}

// ValidateCommand validates a command against the allowlist
func ValidateCommand(parts []string) error {
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	subcommand := parts[0]
	if !allowedSubcommands[subcommand] {
		return fmt.Errorf("subcommand '%s' is not allowed", subcommand)
	}

	return nil
}
