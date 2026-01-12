# dnsctl

BIND 9 DNS control tool for automated zone provisioning using catalog zones.

## Overview

`dnsctl` is an SSH-invoked Go CLI tool that runs on a hidden primary BIND server. It automates:

- **Zone lifecycle**: Create/delete authoritative primary zones via RNDC
- **Catalog zones**: Automatically add/remove zones from a BIND catalog zone
- **Record management**: Upsert/delete/get RRsets via RFC2136 dynamic update (TSIG)
- **ACME helpers**: DNS-01 challenge support for Let's Encrypt and other CAs

## Architecture

```
Management Server
       │
       │ SSH
       ▼
┌─────────────────────────────────────────┐
│  Hidden Primary (BIND 9)                │
│                                         │
│  ┌──────────┐      ┌──────────────────┐ │
│  │  dnsctl  │──────▶│    named       │ │
│  │  (Go)    │ RNDC  │  (primary)      │ │
│  └──────────┘      └──────────────────┘ │
│       │                    ▲            │
│       │ RFC2136            │            │
│       │ (TSIG)             │            │
└───────┼────────────────────┼────────────┘
        │                    │
        ▼                    │
   Catalog Zone              │
   (primary)                 │
        │                    │
        └────────────────────┘
                 │ AXFR/NOTIFY
                 ▼
         ┌───────────────┐
         │   Secondaries │
         │  (catalog     │
         │   zones)      │
         └───────────────┘
```

## Installation

1. Build the binary:
   ```bash
   go build -o dnsctl ./cmd/dnsctl
   sudo cp dnsctl /usr/local/bin/
   ```

2. Create configuration:
   ```bash
   sudo mkdir -p /etc/dnsctl
   sudo cp configs/config.yaml.example /etc/dnsctl/config.yaml
   sudo edit /etc/dnsctl/config.yaml  # Adjust paths and settings
   ```

3. Generate TSIG key:
   ```bash
   sudo tsig-keygen -a hmac-sha256 dnsctl-updater > /etc/dnsctl/tsig.secret
   sudo chmod 0600 /etc/dnsctl/tsig.secret
   ```

4. Configure BIND:
   - Add the TSIG key to `named.conf`
   - Configure catalog zone as primary
   - Set `allow-new-zones yes;`
   - Restrict catalog/zone updates to the TSIG key

5. Test:
   ```bash
   sudo dnsctl doctor
   ```

## Usage

### Zone Management

```bash
# Create a new zone
dnsctl zone create example.com

# Delete a zone
dnsctl zone delete example.com

# Check zone status
dnsctl zone status example.com

# List zones
dnsctl zone list
```

### Record Management

```bash
# Add or replace an A record
dnsctl rrset upsert example.com www A 192.0.2.1 --ttl 3600

# Add an AAAA record
dnsctl rrset upsert example.com www AAAA 2001:db8::1

# Create a CNAME
dnsctl rrset upsert example.com api CNAME example.com

# Delete a record
dnsctl rrset delete example.com www A

# Query a record
dnsctl rrset get example.com www A
```

### ACME Challenges

```bash
# Present a challenge
dnsctl acme present example.com _acme-challenge.example.com "validation_token"

# Cleanup a challenge
dnsctl acme cleanup example.com _acme-challenge.example.com "validation_token"
```

## Configuration

See `configs/config.yaml.example` for all options.

Key settings:

| Setting | Description |
|---------|-------------|
| `bind.rndc_path` | Path to `rndc` binary |
| `bind.rndc_conf` | Path to `rndc.conf` |
| `catalog.zone` | Catalog zone FQDN (with trailing dot) |
| `zones.dir` | Zone file directory |
| `tsig.secret_file` | TSIG key file path (0600) |

## Security Model

- **SSH-only operation**: No inbound TCP ports required
- **TSIG authentication**: All updates are TSIG-signed
- **SSH forced-command**: Restrict to specific subcommands
- **Policy enforcement**: Apex CNAME rejection, NS update restrictions
- **Per-zone locking**: Advisory file locks prevent race conditions

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Validation error |
| 3 | Precondition failure |
| 4 | Runtime failure |
| 5 | Conflict/unsafe |
| 6 | Internal error |

## Dependencies

- `github.com/dlukt/namedconf` - BIND named.conf parser/writer
- `github.com/dlukt/namedzone` - Typed API for named.conf
- `github.com/miekg/dns` - RFC2136 + TSIG implementation
- `github.com/spf13/cobra` - CLI framework

## Spec Compliance

This implementation follows the dnsctl specification:
- Zone lifecycle with catalog zones (RFC 9492)
- RFC2136 dynamic updates with TSIG
- Idempotent catalog membership (sha1-wire labels)
- DNSSEC enabled by default (inline-signing)

## License

MIT
