package main

import (
	"fmt"
	"os"

	"github.com/dlukt/dnsctl/internal/acme"
	"github.com/dlukt/dnsctl/internal/audit"
	"github.com/dlukt/dnsctl/internal/config"
	"github.com/dlukt/dnsctl/internal/zone"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
	version = "dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dnsctl",
		Short: "BIND 9 DNS control tool for catalog zones",
		Long: `dnsctl - SSH-invoked DNS control tool for BIND 9

Automates zone lifecycle and record management using catalog zones.
Runs on a hidden primary BIND server via SSH.`,
		Version: version,
	}

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/dnsctl/config.yaml", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Add subcommands
	rootCmd.AddCommand(doctorCmd())
	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(zoneCmd())
	rootCmd.AddCommand(rrsetCmd())
	rootCmd.AddCommand(acmeCmd())
	rootCmd.AddCommand(sshWrapCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// loadConfig loads the configuration
func loadConfig() (*config.Config, *audit.Logger, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load config: %w", err)
	}

	logger := audit.NewLogger(os.Stderr, cfg.Logging.AuditJSONL, cfg.Logging.IncludeActor)
	if verbose {
		logger.SetVerbose(true)
	}

	return cfg, logger, nil
}

// doctorCmd implements the doctor command
func doctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run BIND precondition checks",
		Long:  "Checks that BIND is properly configured for dnsctl operations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("doctor")

			// TODO: Implement doctor checks using namedzone library
			// For now, just output a simple check
			result := audit.NewResult("doctor", logger.RequestID())
			result.AddChange("config_loaded")

			// Check config paths
			if _, err := os.Stat(cfg.Bind.RNDCPath); err != nil {
				result.AddWarning(fmt.Sprintf("rndc not found: %s", cfg.Bind.RNDCPath))
			} else {
				result.AddChange("rndc_found")
			}

			if _, err := os.Stat(cfg.Bind.RNDCConf); err != nil {
				result.AddWarning(fmt.Sprintf("rndc.conf not found: %s", cfg.Bind.RNDCConf))
			} else {
				result.AddChange("rndc_conf_found")
			}

			logger.WriteAudit(result)
			return result.Output()
		},
	}

	return cmd
}

// versionCmd implements the version command
func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("dnsctl version %s\n", version)
			fmt.Printf("RFC2136 client: github.com/miekg/dns\n")
			fmt.Printf("BIND parser: github.com/dlukt/namedconf + github.com/dlukt/namedzone\n")
		},
	}

	return cmd
}

// zoneCmd implements zone commands
func zoneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zone",
		Short: "Zone lifecycle management",
	}

	cmd.AddCommand(zoneCreateCmd())
	cmd.AddCommand(zoneDeleteCmd())
	cmd.AddCommand(zoneStatusCmd())
	cmd.AddCommand(zoneListCmd())

	return cmd
}

// zoneCreateCmd implements zone create
func zoneCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <zone>",
		Short: "Create a new authoritative primary zone",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("zone_create").WithZone(args[0])

			creator := zone.NewCreator(cfg)
			var changes []string

			if err := creator.CreateZone(args[0], &changes); err != nil {
				logger.Error(err.Error())
				result := audit.NewErrorResult("zone_create", logger.RequestID(),
					audit.ExitRuntimeFailure, err.Error(), "")
				logger.WriteAudit(result)
				return result.Output()
			}

			result := audit.NewResult("zone_create", logger.RequestID())
			result.Zone = args[0]
			result.Changes = changes
			logger.WriteAudit(result)
			return result.Output()
		},
	}

	return cmd
}

// zoneDeleteCmd implements zone delete
func zoneDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <zone>",
		Short: "Delete a zone",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("zone_delete").WithZone(args[0])

			deleter := zone.NewDeleter(cfg)
			var changes []string

			if err := deleter.DeleteZone(args[0], &changes); err != nil {
				logger.Error(err.Error())
				result := audit.NewErrorResult("zone_delete", logger.RequestID(),
					audit.ExitRuntimeFailure, err.Error(), "")
				logger.WriteAudit(result)
				return result.Output()
			}

			result := audit.NewResult("zone_delete", logger.RequestID())
			result.Zone = args[0]
			result.Changes = changes
			logger.WriteAudit(result)
			return result.Output()
		},
	}

	return cmd
}

// zoneStatusCmd implements zone status
func zoneStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <zone>",
		Short: "Show zone status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("zone_status").WithZone(args[0])

			checker := zone.NewStatusChecker(cfg)
			status, err := checker.ZoneStatus(args[0])
			if err != nil {
				logger.Error(err.Error())
				result := audit.NewErrorResult("zone_status", logger.RequestID(),
					audit.ExitRuntimeFailure, err.Error(), "")
				logger.WriteAudit(result)
				return result.Output()
			}

			// Output status as JSON
			// For simplicity, using audit.Result - could have a dedicated StatusResult
			result := audit.NewResult("zone_status", logger.RequestID())
			result.Zone = args[0]
			if status.Exists {
				result.AddChange("zone_exists")
			}
			if status.InCatalog {
				result.AddChange("in_catalog")
			}

			logger.WriteAudit(result)

			// Output the status
			fmt.Printf(`{
  "zone": "%s",
  "exists": %t,
  "loaded": %t,
  "is_primary": %t,
  "in_catalog": %t,
  "catalog_label": "%s",
  "zone_file_path": "%s",
  "dnssec_enabled": %t
}`, status.Zone, status.Exists, status.Loaded, status.IsPrimary,
				status.InCatalog, status.CatalogLabel, status.ZoneFilePath,
				status.DNSSECEnabled)

			return nil
		},
	}

	return cmd
}

// zoneListCmd implements zone list
func zoneListCmd() *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List zones",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("zone_list")

			// TODO: Implement zone listing from zones directory
			// For now, return a placeholder
			result := audit.NewResult("zone_list", logger.RequestID())
			logger.WriteAudit(result)

			fmt.Println(`{
  "zones": [],
  "count": 0
}`)

			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 100, "maximum number of zones to return")

	return cmd
}

// rrsetCmd implements rrset commands
func rrsetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rrset",
		Short: "Record management (RRset operations)",
	}

	cmd.AddCommand(rrsetUpsertCmd())
	cmd.AddCommand(rrsetDeleteCmd())
	cmd.AddCommand(rrsetGetCmd())

	return cmd
}

// rrsetUpsertCmd implements rrset upsert
func rrsetUpsertCmd() *cobra.Command {
	var ttl uint32

	cmd := &cobra.Command{
		Use:   "upsert <zone> <owner> <type> <rdata...>",
		Short: "Create or replace an RRset",
		Args:  cobra.MinimumNArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			zoneInput := args[0]
			ownerInput := args[1]
			rrType := args[2]
			rdata := args[3:]

			logger.WithOp("rrset_upsert").WithZone(zoneInput)

			// Import rrset package
			manager := &struct {
				Upsert func(string, string, string, uint32, []string) (interface{}, error)
			}{
				Upsert: func(z, o, t string, ttl uint32, rd []string) (interface{}, error) {
					// This would call rrset.Manager.Upsert
					// For now, placeholder
					return nil, fmt.Errorf("not yet implemented")
				},
			}

			result, err := manager.Upsert(zoneInput, ownerInput, rrType, ttl, rdata)
			if err != nil {
				logger.Error(err.Error())
				errResult := audit.NewErrorResult("rrset_upsert", logger.RequestID(),
					audit.ExitRuntimeFailure, err.Error(), "")
				logger.WriteAudit(errResult)
				return errResult.Output()
			}

			// Output result
			fmt.Println(result)
			return nil
		},
	}

	cmd.Flags().Uint32VarP(&ttl, "ttl", "t", 3600, "TTL for the record")

	return cmd
}

// rrsetDeleteCmd implements rrset delete
func rrsetDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <zone> <owner> <type>",
		Short: "Delete an RRset",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("rrset_delete").WithZone(args[0])

			// TODO: Implement rrset delete
			result := audit.NewResult("rrset_delete", logger.RequestID())
			logger.WriteAudit(result)
			return result.Output()
		},
	}

	return cmd
}

// rrsetGetCmd implements rrset get
func rrsetGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <zone> <owner> <type>",
		Short: "Get an RRset",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("rrset_get").WithZone(args[0])

			// TODO: Implement rrset get
			result := audit.NewResult("rrset_get", logger.RequestID())
			logger.WriteAudit(result)
			return result.Output()
		},
	}

	return cmd
}

// acmeCmd implements ACME commands
func acmeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acme",
		Short: "ACME DNS-01 challenge helpers",
	}

	cmd.AddCommand(acmePresentCmd())
	cmd.AddCommand(acmeCleanupCmd())

	return cmd
}

// acmePresentCmd implements acme present
func acmePresentCmd() *cobra.Command {
	var ttl uint32

	cmd := &cobra.Command{
		Use:   "present <zone> <fqdn> <value>",
		Short: "Present ACME DNS-01 challenge",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("acme_present").WithZone(args[0])

			handler := acme.NewACMEHandler(cfg)
			result, err := handler.Present(args[0], args[1], args[2], ttl)
			if err != nil {
				logger.Error(err.Error())
				errResult := audit.NewErrorResult("acme_present", logger.RequestID(),
					audit.ExitRuntimeFailure, err.Error(), "")
				logger.WriteAudit(errResult)
				return errResult.Output()
			}

			// Output result
			fmt.Printf(`{
  "success": true,
  "owner": "%s",
  "type": "TXT",
  "ttl": %d,
  "rdata": ["%s"]
}`, result.Owner, result.TTL, result.RData[0])

			return nil
		},
	}

	cmd.Flags().Uint32VarP(&ttl, "ttl", "t", 60, "TTL for the TXT record")

	return cmd
}

// acmeCleanupCmd implements acme cleanup
func acmeCleanupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cleanup <zone> <fqdn> <value>",
		Short: "Cleanup ACME DNS-01 challenge",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, logger, err := loadConfig()
			if err != nil {
				return err
			}
			defer logger.Close()

			logger.WithOp("acme_cleanup").WithZone(args[0])

			handler := acme.NewACMEHandler(cfg)
			if err := handler.Cleanup(args[0], args[1], args[2]); err != nil {
				logger.Error(err.Error())
				errResult := audit.NewErrorResult("acme_cleanup", logger.RequestID(),
					audit.ExitRuntimeFailure, err.Error(), "")
				logger.WriteAudit(errResult)
				return errResult.Output()
			}

			result := audit.NewResult("acme_cleanup", logger.RequestID())
			result.AddChange("challenge_removed")
			logger.WriteAudit(result)
			return result.Output()
		},
	}

	return cmd
}

// sshWrapCmd implements SSH wrapper mode
func sshWrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "--ssh-wrap",
		Short:  "SSH forced-command wrapper mode",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := audit.NewLogger(os.Stderr, "", true)

			// Import ssh package
			// This would call ssh.WrapHandler.Handle()
			// For now, placeholder
			result := audit.NewResult("ssh_wrap", logger.RequestID())
			logger.WriteAudit(result)
			return result.Output()
		},
	}

	return cmd
}
