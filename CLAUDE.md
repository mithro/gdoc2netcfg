# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
uv run pytest                           # Run all tests
uv run pytest tests/test_models/        # Run tests for a specific module
uv run pytest tests/test_models/test_addressing.py::test_mac_parse  # Run single test
uv run pytest -x                        # Stop on first failure
uv run ruff check src/ tests/           # Lint
uv run gdoc2netcfg fetch                # Download CSVs from Google Sheets
uv run gdoc2netcfg generate dnsmasq_internal  # Generate internal dnsmasq config
uv run gdoc2netcfg generate dnsmasq_external  # Generate external dnsmasq config
uv run gdoc2netcfg generate letsencrypt       # Generate certbot cert scripts
uv run gdoc2netcfg generate nagios            # Generate Nagios monitoring config
uv run gdoc2netcfg generate nginx             # Generate nginx reverse proxy configs
uv run gdoc2netcfg generate topology          # Generate Graphviz DOT topology diagram
uv run gdoc2netcfg generate known_hosts        # Generate SSH known_hosts file
uv run gdoc2netcfg validate             # Run constraint validation
uv run gdoc2netcfg info                 # Show pipeline configuration
uv run gdoc2netcfg reachability         # Ping all hosts and report up/down
uv run gdoc2netcfg sshfp --force        # Scan SSH fingerprints
uv run gdoc2netcfg known-hosts --force  # Scan SSH host keys (for known_hosts)
uv run gdoc2netcfg ssl-certs --force    # Scan SSL/TLS certificates
uv run gdoc2netcfg snmp-host --force    # Scan hosts for SNMP system info
uv run gdoc2netcfg snmp-switch --force  # Scan switches for bridge/topology via SNMP
uv run gdoc2netcfg bmc-firmware --force # Probe BMC firmware versions via ipmitool
uv run gdoc2netcfg bridge              # Unified switch data (SNMP + NSDP)
uv run gdoc2netcfg nsdp                # Scan Netgear switches via NSDP
uv run gdoc2netcfg cron                # Manage scheduled cron jobs
uv run gdoc2netcfg password <query>        # Look up device password by hostname/MAC/IP
uv run gdoc2netcfg password --type snmp <query>  # Look up SNMP community string
uv run gdoc2netcfg password --type ipmi <query>  # Look up IPMI credentials
uv run gdoc2netcfg password --quiet <query>      # Output password only (for piping)
uv run gdoc2netcfg tasmota scan --force    # Scan IoT VLAN for Tasmota devices
uv run gdoc2netcfg tasmota show            # Show cached Tasmota device data
uv run gdoc2netcfg tasmota configure --dry-run --all  # Preview config changes
uv run gdoc2netcfg tasmota configure <host>      # Push config to a specific device
uv run gdoc2netcfg tasmota ha-status       # Check Home Assistant integration
uv run gdoc2netcfg reachability publish --force    # One-shot MQTT publish
uv run gdoc2netcfg reachability publish --daemon   # MQTT daemon (5min interval)
uv run scripts/ha-create-reachability-dashboard.py # Generate & deploy HA dashboard
```

Always use `uv run` to execute Python commands. Never use bare `python` or `pip`.

## Development Workflow

Make small, discrete commits as you work. Each logical unit of change (adding a helper function, wiring a parameter through the call chain, adding tests, updating docs) should be its own commit. Don't batch all changes into a single commit at the end.

### Fail Loud, Never Fabricate

**Never make up data.** If a value can't be resolved, computed, or looked up — raise an error. Don't generate synthetic placeholders, fallback names, or default values that hide the problem. Examples of things to never do:
- Generating a fake port name like `f"port{bridge_port}"` when an ifIndex lookup fails
- Substituting a default value when a required field is missing
- Silently returning `None` or an empty result when something unexpected happens

**Never silently discard data.** If a record, entry, or value can't be processed — raise an error. Don't skip it with `continue` or filter it out. Every piece of input data matters and unexpected data indicates a bug or a gap in our understanding that needs investigation.

**Fail early and loud** so problems surface immediately and get fixed at the root cause. Silent fallbacks and graceful degradation turn small bugs into hard-to-diagnose data quality issues.

## Architecture

`gdoc2netcfg` reads network device data from a Google Spreadsheet and generates configuration files for network infrastructure services (dnsmasq, Nagios, nginx).

### Pipeline

The system is a data pipeline in `src/gdoc2netcfg/`:

```
Sources (sources/)     Fetch CSV from Google Sheets, cache locally, parse into DeviceRecord
    │                  Also parses VLAN Allocations sheet (vlan_parser.py)
    │
Derivations (derivations/)  Pure functions: IPv4→IPv6, IP→VLAN, hostname, DHCP name, DNS names,
    │                        default IP, hardware type detection, site IP remapping
    │                        host_builder.py orchestrates these into Host objects
    │
Supplements (supplements/)  External enrichment (all cached to .cache/):
    │                        SSHFP (ssh-keyscan), SSL certs, SNMP host info, SNMP bridge/topology,
    │                        BMC firmware (ipmitool), NSDP switch discovery, reachability (ping)
    │
Constraints (constraints/)  Validation: field presence, BMC placement, MAC uniqueness,
    │                        IPv6 consistency, bridge/topology, SNMP availability, SSL certs
    │
Generators (generators/)    Output: dnsmasq_internal, dnsmasq_external, nagios, nginx,
    │                        letsencrypt, topology (Graphviz DOT)
    │
Config files               Per-host .conf files in output directories
```

Supporting modules:
- `utils/` — shared helpers: IP sort/classification (`ip.py`), DNS/path injection guards (`dns.py`), terminal colours (`terminal.py`)
- `audit/` — compare spreadsheet data against live network state

The CLI (`cli/main.py`) wires the pipeline via `_build_pipeline()` which returns `(records, hosts, inventory, validation_result)`. Generators receive a `NetworkInventory` — the fully enriched model with all derivations applied.

### Key Data Flow

1. `sources/parser.py` parses CSV rows into `DeviceRecord` (machine, mac, ip, interface)
2. `derivations/host_builder.py::build_hosts()` groups records by machine name into `Host` objects, each with multiple `NetworkInterface` entries
3. `derivations/dns_names.py::derive_all_dns_names()` computes all DNS name variants per host (hostname, interface, subdomain, ipv4/ipv6 prefix variants)
4. `build_inventory()` creates `NetworkInventory` with precomputed `ip_to_hostname` and `ip_to_macs` indexes
5. Generators consume `NetworkInventory` to produce config files

### BMC Handling

BMCs (Baseboard Management Controllers) are physically separate machines attached to a primary host. When a spreadsheet row has interface="bmc" on machine="big-storage", `build_hosts()` creates a separate host `bmc.big-storage` — not a sub-interface. The BMC gets its own hostname, DNS records, DHCP binding, and PTR entry.

### IPv4→IPv6 Mapping

Dual-stack addressing uses the scheme: `10.AA.BB.CCC` → `{prefix}AABB::CCC` where AA is unpadded and BB is zero-padded to 2 digits. Prefixes are configured under `[ipv6]` in the site's `gdoc2netcfg.toml`.

### Split-Horizon DNS

The dnsmasq generator has internal and external variants. Both produce per-host `.conf` files and share PTR, host-record, CAA, and SSHFP generation via `dnsmasq_common.py`. The internal generator additionally produces DHCP host bindings. External (`dnsmasq_external.py`) replaces RFC 1918 IPs with the site's public IPv4 address in host-record entries for external-facing DNS. PTR records use the original IPs in both variants (IPv4 PTRs use RFC 1918 addresses; IPv6 PTRs use globally routable addresses).

### Let's Encrypt Certificates

The letsencrypt generator (`letsencrypt.py`) produces per-host certbot scripts in `certs-available/{primary_fqdn}` and a `renew-enabled.sh` orchestrator. Uses DNS-01 challenge validation via the `certbot-hook-dnsmasq` Python CLI (`certbot-hook-dnsmasq auth-hook`) that manages `_acme-challenge` TXT records in the external dnsmasq instance. Dnsmasq connection parameters (`--conf-dir`, `--conf`, `--service`) are passed as CLI flags on the auth hook command rather than environment variables. Deploy hooks are added based on `hardware_type` (e.g. supermicro-bmc, netgear-switch). Only public FQDNs (`is_fqdn=True`) are included as `-d` domains.

### Nginx Reverse Proxy

The nginx generator (`nginx.py`) produces per-host config directories under `sites-available/{fqdn}/`. Each host gets three files: `http-proxy.conf` (HTTP reverse proxy on port 80), `https-upstream.conf` (stream upstream for TLS passthrough), and `https-map.conf` (SNI map entries). Multi-interface hosts additionally get `http-healthcheck.lua`, `https-healthcheck.lua`, and `https-balancer.lua` in their directory.

HTTPS is handled via stream SNI passthrough rather than http-module HTTPS blocks, ensuring consistent TLS behaviour for both IPv4 (proxied) and IPv6 (direct) paths. HTTP blocks include inline ACME challenge locations with `try_files` fallback to the backend for hosts handling their own ACME challenges.

Multi-interface hosts get a combined HTTP config file containing an `upstream` block listing all interface IPs for round-robin failover with `proxy_next_upstream`, a root server block using the upstream, and per-interface server blocks with direct `proxy_pass`. Their HTTPS upstream uses `balancer_by_lua_file` for health-aware peer selection via a custom Lua HTTPS health checker (`scripts/checker.lua`). Single-interface hosts produce simple direct `proxy_pass` configs and direct stream server entries.

All generated files live under a single deployment root (`gdoc2netcfg_dir`, default `/etc/nginx/gdoc2netcfg/`). Enabling a host is a single symlink: `ln -s /etc/nginx/gdoc2netcfg/sites-available/{fqdn} /etc/nginx/sites-enabled/{fqdn}`. Removing all generated configs is `rm -rf /etc/nginx/gdoc2netcfg`.

### Network Topology

The topology generator (`topology.py`) produces a Graphviz DOT diagram of the physical network from bridge supplement data. Switch nodes (hosts with bridge data) are boxes; host nodes (whose MACs appear in switch MAC tables) are ellipses. LLDP-learned edges are bold and bidirectional; MAC-learned edges are dashed. Locally administered MACs are filtered out.

### Configuration

`gdoc2netcfg.toml` (gitignored, site-specific) defines site topology (domain, VLANs, IPv6 prefixes, network subdomains), sheet URLs, cache directory, and generator settings. Loaded by `config.py` into a `PipelineConfig` dataclass containing a `Site` object.

`gdoc2netcfg.toml.example` is the tracked template with Welland defaults. Each site copies it to `gdoc2netcfg.toml` and edits the `[site]`, `[ipv6]`, and `[generators] enabled` sections. This avoids merge conflicts when deploying to Monarto.

### Models

- `MACAddress`, `IPv4Address`, `IPv6Address` — frozen, validated, normalized value types in `models/addressing.py`
- `Host` — groups `NetworkInterface` entries for one machine, with default IP selection; `VirtualInterface` for derived interfaces
- `NetworkInventory` — the complete enriched model passed to generators
- `VLAN`, `Site` — network topology definitions in `models/network.py`, loaded from config + VLAN Allocations sheet
- `PortLinkStatus`, `PortTrafficStats`, `SwitchData`, `SwitchDataSource` — unified switch data model in `models/switch_data.py`, populated from SNMP or NSDP sources

**Credential columns**: The spreadsheet may include extra columns such as `Password`, `SNMP Community`, `IPMI Username`, `IPMI Password` which are preserved in `Host.extra` and accessible via the `password` CLI command.

### NSDP Protocol Library

`src/nsdp/` is a standalone pure-Python implementation of the Netgear Switch Discovery Protocol (NSDP). It has no external dependencies. The `supplements/nsdp.py` module bridges this library into the gdoc2netcfg supplement pipeline. See `docs/nsdp-protocol.md` for the protocol specification.

### MQTT Reachability Publishing

`src/gdoc2netcfg/supplements/mqtt_ha.py` publishes host reachability data to Home Assistant via MQTT discovery. Each host becomes an HA device with connectivity, presence, stack mode, and per-interface diagnostic entities (IPv4, MAC, RTT).

**Entity ID scheme**: Uses `_node_id(host.hostname)` (not `machine_name`) to derive entity IDs. This ensures BMC hosts get unique IDs — BMCs share `machine_name` with their parent (e.g. both `big-storage` and `bmc.big-storage` have `machine_name="big-storage"`), but have distinct hostnames. Entity IDs include the VLAN subdomain (e.g. `gdoc2netcfg_au_plug_1_iot_connectivity` not `gdoc2netcfg_au_plug_1_connectivity`).

**Discovery payloads** are published with `retain=True` so HA rediscovers entities on restart. **State messages** are NOT retained — `expire_after` (600s) handles staleness. Bridge availability uses LWT for automatic offline marking.

**Daemon mode**: `uv run gdoc2netcfg reachability publish --daemon --interval 300` runs as a persistent service, scanning reachability every 5 minutes and publishing discovery + state to MQTT. Managed by `gdoc2netcfg-reachability.service` systemd unit. After deploying code changes that affect MQTT publishing, the daemon must be restarted: `sudo systemctl restart gdoc2netcfg-reachability.service`.

**One-shot mode**: `uv run gdoc2netcfg reachability publish --force` runs a single scan and publishes.

### Network Reachability Dashboard

`scripts/ha-create-reachability-dashboard.py` generates a self-contained HTML dashboard and deploys it to HA's `/config/www/` directory via SSH. The dashboard is embedded in HA as a Lovelace iframe panel at `/network-reachability/default`.

**Architecture**: The Python script bakes STRUCTURAL data (host list, network grouping, entity ID prefixes, FQDNs, PoE port mappings) into the HTML as JSON. The HTML's JavaScript connects to HA's WebSocket API at runtime for LIVE entity states (connectivity, RTT, stack mode, plug/PoE on/off). No periodic regeneration is needed for status updates — data updates in real-time via WebSocket subscription.

**Regeneration**: Only needed when the network STRUCTURE changes (new hosts added, PoE ports remapped, VLAN changes). Run from the dev repo:

```bash
uv run scripts/ha-create-reachability-dashboard.py
```

This fetches PoE port mappings from HA, generates the HTML, SCPs it to HA, and updates the iframe dashboard config with a cache-busting URL.

**Features**:
- Hosts grouped by network (VLAN subdomain) in sortable tables
- All columns sortable with natural sort (click headers)
- Multi-interface hosts fold/unfold (click ▶/▼ in col 2)
- Single-interface hosts show on one row
- Host links use stack-dependent DNS prefix (bare FQDN for dual-stack, `ipv4.`/`ipv6.` for single-stack)
- Controls column shows Tasmota plugs (🔌) and PoE ports (⚡) with live on/off state
- Dark/light theme detection from HA parent frame

**Files**:
- `scripts/ha-create-reachability-dashboard.py` — generator + deployer (both dashboards)
- `scripts/ha-reachability-dashboard.html` — host reachability HTML template
- `scripts/ha-switch-dashboard.html` — switch port HTML template

### Switch Port Dashboard

A second tab under the same HA panel (`/network-reachability/switches`) showing per-port switch state. Same architecture: Python bakes structural data (switch list, port numbers) into HTML; JS connects to HA WebSocket for live data.

**Connected device resolution**: Port descriptions (live from HA) are parsed to extract hostname, then looked up in `sensor.gdoc2netcfg_host_directory` (published by the reachability daemon) to get the full hostname and derive entity IDs for live MAC/IPv4/IPv6 lookup.

**Port table columns**: Port, Link, Speed, Description, VLAN, PoE (toggleable), Host, Interface, IPv4, IPv6, MAC, LLDP, mismatch warning. All sortable per-switch.

**LLDP mismatch warning**: Orange warning icon when hostname parsed from description differs from LLDP neighbor name.

**Regeneration**: Same as reachability dashboard — only needed when switch structure changes (new switches, port count changes):

```bash
uv run scripts/ha-create-reachability-dashboard.py
```

This generates and deploys both dashboards, then configures the two-view HA panel.

## Production Deployment

Deployed on two sites, both at `/opt/gdoc2netcfg/`:

| Site | Host | IP scheme | IPv6 prefix | Generators |
|------|------|-----------|-------------|------------|
| welland | `ten64.welland.mithis.com` (10.1.10.1) | `10.1.X.X` | `2404:e80:a137:1XX::` | internal, external, nagios, nginx |
| monarto | `ten64.monarto.mithis.com` (10.2.10.1) | `10.2.X.X` | `2404:e80:a137:2XX::` | internal only |

Both sites share the same Google Spreadsheet. The spreadsheet uses `10.X.Y.Z` (literal `X` in the second octet) for devices that exist at multiple sites, and a "Site" column to restrict records to a specific site. The `site_octet` in each site's `gdoc2netcfg.toml` replaces the `X` placeholder.

### Deploying code changes

Use SSH agent forwarding and `sudo -E` so that `git pull` can authenticate via the forwarded SSH key:

```bash
# Welland
ssh -A ten64.welland.mithis.com "cd /opt/gdoc2netcfg && sudo -E git pull"

# Monarto (via WireGuard tunnel)
ssh -o ControlPath=none -o ForwardAgent=yes tim@10.255.0.2 \
  "cd /opt/gdoc2netcfg && sudo -E git pull"
```

`git pull` is clean on both sites — `gdoc2netcfg.toml` is gitignored, so each site's local config is never touched by pulls. After pulling changes that affect MQTT publishing (`mqtt_ha.py`), restart the reachability daemon:

```bash
sudo systemctl restart gdoc2netcfg-reachability.service
```

If a site doesn't have a local config yet, create one after pulling:

```bash
cp gdoc2netcfg.toml.example gdoc2netcfg.toml
# Edit [site], [ipv6], and [generators] enabled for this site
```

Note: `uv` on monarto is at `~/.local/bin/uv` (not in PATH for non-interactive shells).

### dnsmasq

#### Directory layout

dnsmasq instances run via systemd template units (`dnsmasq@internal`, `dnsmasq@external`). Each instance has a top-level config at `/etc/dnsmasq.d/dnsmasq.{instance}.conf` with `conf-dir` directives:

```
/etc/dnsmasq.d/
  dnsmasq.internal.conf          # conf-dir=shared, internal, internal/generated
  dnsmasq.external.conf          # conf-dir=shared, external, external/generated (welland only)
  shared/                        # Shared config (base, upstream, logging, edns)
  internal/
    00-listen.conf               # Listen addresses, bind-dynamic
    02-cross-site.conf           # Cross-site DNS forwarding via WireGuard
    03-auth-server.conf          # Auth DNS server config
    04-dhcp-global.conf          # DHCP global settings
    network-*.conf               # Per-VLAN DHCP ranges and domains
    override-*.conf              # Manual per-device overrides
    generated/                   # ← gdoc2netcfg output (wipe-and-replace safe)
      ten64.conf
      desktop.conf
      ...
  external/                      # Welland only
    00-listen.conf
    03-auth-dns.conf
    dnsmasq.acme.*.conf          # ACME challenge records
    generated/                   # ← gdoc2netcfg output (wipe-and-replace safe)
      ...
```

Hand-crafted configs live in `internal/` and `external/`. Generated per-host configs live in `internal/generated/` and `external/generated/`. The `generated/` subdirectories can be wiped and replaced without affecting manual configs.

#### Fetch, generate, and deploy

```bash
# On each site:
cd /opt/gdoc2netcfg
uv run gdoc2netcfg fetch
uv run gdoc2netcfg generate --force

# Deploy (wipe old generated configs, copy new ones)
sudo rm -f /etc/dnsmasq.d/internal/generated/*.conf
sudo cp internal/*.conf /etc/dnsmasq.d/internal/generated/
sudo systemctl restart dnsmasq@internal

# Welland also has external:
sudo rm -f /etc/dnsmasq.d/external/generated/*.conf
sudo cp external/*.conf /etc/dnsmasq.d/external/generated/
sudo systemctl restart dnsmasq@external
```

#### Cross-site DNS forwarding

The two sites forward DNS queries to each other via WireGuard tunnel (`10.255.0.1` welland, `10.255.0.2` monarto). Each site's `02-cross-site.conf` contains `server=` directives to forward the other site's domains, reverse IPv4 zones (`X.10.in-addr.arpa`), and reverse IPv6 zones through the tunnel.

### nginx

Generated nginx configs are deployed to `/etc/nginx/gdoc2netcfg/` (per-host directories under `sites-available/`, plus `scripts/`, `conf.d/`, `stream.d/` for healthcheck infrastructure). Hosts are activated via symlinks: `ln -s /etc/nginx/gdoc2netcfg/sites-available/{fqdn} /etc/nginx/sites-enabled/{fqdn}`. Welland only.

### Let's Encrypt

Certbot scripts are generated to `/opt/gdoc2netcfg/letsencrypt/`. Welland only.

```bash
sudo uv run gdoc2netcfg generate --output-dir /opt/gdoc2netcfg letsencrypt
sudo sh /opt/gdoc2netcfg/letsencrypt/certs-available/{fqdn}  # Provision a cert
```

The auth hook is the `certbot-hook-dnsmasq` Python CLI installed at `/opt/certbot/bin/certbot-hook-dnsmasq` (separate repo: `mithro/certbot-hook-dnsmasq`). It creates TXT records in the external dnsmasq, verifies local resolution, sends NOTIFY to secondaries, and polls until they sync.

### Looking up device credentials

On either site, look up credentials from the cached spreadsheet data:

```bash
cd /opt/gdoc2netcfg
uv run gdoc2netcfg password switch1              # Password for switch1
uv run gdoc2netcfg password --quiet 10.1.10.1    # Password only (pipe to clipboard etc.)
uv run gdoc2netcfg password --type snmp switch1   # SNMP community string
uv run gdoc2netcfg password --type ipmi bmc.server1  # IPMI username + password
```

The command reads from the local CSV cache (`gdoc2netcfg fetch` must have been run at least once). It does not contact the Google Sheet directly.

### Other

The SSH host key cache lives at `.cache/ssh_host_keys.json`. SSHFP records are derived from these keys at runtime.
