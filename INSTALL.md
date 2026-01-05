# dnsctl Installation Guide

This guide covers deploying dnsctl on a BIND 9 hidden primary server with catalog zones.

## Prerequisites

- BIND 9.18+ with catalog zone support (RFC 9492)
- Go 1.21+ to build from source
- SSH access to the BIND server
- Root or sudo access

## Quick Start

```bash
# 1. Build and install
go build -o dnsctl ./cmd/dnsctl
sudo cp dnsctl /usr/local/bin/
sudo chmod 0755 /usr/local/bin/dnsctl

# 2. Create directories
sudo mkdir -p /etc/dnsctl
sudo mkdir -p /var/lib/dnsctl/zones
sudo mkdir -p /run/dnsctl/locks
sudo mkdir -p /var/log/dnsctl

# 3. Generate TSIG key
sudo tsig-keygen -a hmac-sha256 dnsctl-updater > /etc/dnsctl/tsig.secret
sudo chmod 0600 /etc/dnsctl/tsig.secret

# 4. Copy config
sudo cp configs/config.yaml.example /etc/dnsctl/config.yaml
sudo $EDITOR /etc/dnsctl/config.yaml

# 5. Test
sudo dnsctl doctor
```

## Detailed Configuration

### 1. BIND Configuration

Add to your `named.conf` or `named.conf.local`:

```bind
// TSIG key for dnsctl updates
key "dnsctl-updater." {
    algorithm hmac-sha256;
    secret "<contents of /etc/dnsctl/tsig.secret>";
};

// Catalog zone (primary)
zone "catalog.example" {
    type primary;
    file "/var/lib/bind/catalog.example.zone";
    journal "/var/lib/bind/catalog.example.zone.jnl";
    allow-update { key "dnsctl-updater."; };
    // Don't allow transfers except to secondaries
    allow-transfer { 192.0.2.10; 192.0.2.11; };
};

// Options for dynamic zones
options {
    // Allow adding new zones via RNDC
    allow-new-zones yes;

    // DNS update settings
    allow-update-v6 { none; };
    allow-recursion { none; };
    allow-query-cache { none; };

    // Catalog zone settings
    catalog-zones { catalog.example; };
};
```

### 2. Create Initial Catalog Zone

```bash
sudo tee /var/lib/bind/catalog.example.zone > /dev/null <<EOF
\$ORIGIN catalog.example.
\$TTL 60
@   IN  SOA localhost. admin.example.com. (
        1          ; serial
        3600       ; refresh
        1800       ; retry
        604800     ; expire
        60 )       ; minimum
    IN  NS  localhost.
EOF

sudo chown bind:bind /var/lib/bind/catalog.example.zone
sudo chmod 0640 /var/lib/bind/catalog.example.zone
```

Reload BIND:
```bash
sudo rndc reload
```

### 3. Configure dnsctl

Edit `/etc/dnsctl/config.yaml`:

```yaml
bind:
  rndc_path: /usr/sbin/rndc
  rndc_conf: /etc/bind/rndc.conf
  dns_addr: 127.0.0.1
  dns_port: 53
  tcp_updates: true

catalog:
  zone: catalog.example.
  schema_version: 2
  label_algorithm: sha1-wire

zones:
  dir: /var/lib/dnsctl/zones
  file_extension: zone
  file_owner: bind
  file_group: bind
  default_notify: true
  dnssec_policy: default
  inline_signing: true
  update_mode: allow-update
  tsig_key_name: dnsctl-updater.

tsig:
  name: dnsctl-updater.
  algorithm: hmac-sha256
  secret_file: /etc/dnsctl/tsig.secret

policy:
  allowed_rrtypes: [A, AAAA, CNAME, TXT, MX, SRV, CAA]
  disallow_apex_cname: true
  disallow_ns_updates: true
  max_ttl: 86400
  min_ttl: 30

locking:
  dir: /run/dnsctl/locks

logging:
  audit_jsonl: /var/log/dnsctl/audit.jsonl
  include_actor: true
```

### 4. SSH Forced Command (Optional)

For restricted SSH access, add to `/etc/ssh/sshd_config`:

```ssh
# Restrict dnsctl user
Match User dnsctl
    ForceCommand "/usr/local/bin/dnsctl --ssh-wrap"
    PermitTTY no
    AllowTcpForwarding no
    X11Forwarding no
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

## Verification

### 1. Run Doctor Checks

```bash
sudo dnsctl doctor
```

Expected output:
```json
{
  "ok": true,
  "op": "doctor",
  "changes": ["config_loaded", "rndc_found", "rndc_conf_found"]
}
```

### 2. Create Test Zone

```bash
sudo dnsctl zone create test.example.com
```

Expected output:
```json
{
  "ok": true,
  "op": "zone_create",
  "zone": "test.example.com.",
  "changes": [
    "zone_added",
    "catalog_updated"
  ]
}
```

### 3. Verify Catalog Membership

Check that the PTR record was added to the catalog zone:
```bash
dig @localhost PTR c5e4b4da1e5a620ddaa3635e55c3732a5b49c7f4.zones.catalog.example ANY
```

### 4. Add Records

```bash
sudo dnsctl rrset upsert test.example.com www A 192.0.2.1
```

### 5. Cleanup

```bash
sudo dnsctl zone delete test.example.com
```

## Secondary Configuration

On secondary servers, configure the catalog zone:

```bind
zone "catalog.example" {
    type secondary;
    primaries { 192.0.2.1; };  // Hidden primary IP
    allow-transfer { none; };
};
```

When you create zones via dnsctl on the primary, the secondaries will automatically:
1. See the PTR record in the catalog zone
2. Create a secondary zone for the member
3. Transfer the zone data

## Troubleshooting

### RNDC Connection Failed

```bash
# Check rndc is working
sudo rndc status

# Verify config path
sudo ls -la /etc/bind/rndc.conf

# Check permissions
sudo ls -la /etc/rndc.conf
sudo ls -la /etc/bind/rndc.key
```

### TSIG Errors

```bash
# Verify TSIG secret matches
sudo cat /etc/dnsctl/tsig.secret
sudo grep -A1 'key "dnsctl-updater"' /etc/bind/named.conf.local

# Check BIND logs
sudo journalctl -u named -f
```

### Zone Not Created

```bash
# Check BIND is configured for allow-new-zones
sudo named-confconf | grep allow-new-zones

# Check zones directory
sudo ls -la /var/lib/dnsctl/zones

# Check zone exists
sudo rndc zonestatus example.com
```

### Catalog Updates Not Working

```bash
# Verify catalog zone is primary
sudo named-confconf | grep "zone.*catalog"

# Check catalog zone serial
sudo dig @localhost SOA catalog.example

# Test dynamic update
nsupdate -k /etc/dnsctl/tsig.secret <<EOF
server localhost
zone catalog.example
update add test.zones.catalog.example 60 PTR test.example.com.
send
EOF
```

## File Permissions

Recommended permissions:

| Path | Owner | Group | Permissions |
|------|-------|-------|-------------|
| `/usr/local/bin/dnsctl` | root | root | 0755 |
| `/etc/dnsctl/config.yaml` | root | bind | 0640 |
| `/etc/dnsctl/tsig.secret` | root | bind | 0600 |
| `/var/lib/dnsctl/zones` | bind | bind | 0770 |
| `/run/dnsctl/locks` | root | root | 0755 |
| `/var/log/dnsctl/audit.jsonl` | root | bind | 0640 |

## Systemd Service (Optional)

Create `/etc/systemd/system/dnsctl-logrotate.service` for log rotation:

```ini
[Unit]
Description=dnsctl log rotation
Documentation=file:///usr/share/doc/dnsctl/README.md

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate /etc/logrotate.d/dnsctl
```

## Production Checklist

- [ ] BIND 9.18+ installed
- [ ] Catalog zone created and loaded
- [ ] `allow-new-zones yes;` configured
- [ ] TSIG key generated and configured
- [ ] dnsctl config created
- [ ] `dnsctl doctor` passes
- [ ] Test zone created successfully
- [ ] Catalog PTR record appears
- [ ] Secondary can see new zone
- [ ] SSH forced-command configured (if needed)
- [ ] Log rotation configured
- [ ] Monitoring/alerting configured
- [ ] Backup procedure documented
