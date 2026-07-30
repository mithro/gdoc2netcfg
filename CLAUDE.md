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
uv run gdoc2netcfg generate dnsmasq_leaf pdns_internal pdns_external recursor_forward --output-dir out
                                        # Welland DNS stack (out/ mirrors /etc)
uv run gdoc2netcfg generate dnsmasq_internal  # Legacy dnsmasq config (monarto only)
uv run gdoc2netcfg generate dnsmasq_external  # Legacy external config (monarto only)
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
uv run gdoc2netcfg db info             # Show SQLite DB sizes and per-scan_type scan counts
uv run gdoc2netcfg db history          # Show scan history (flags: --type, --since, --limit)
uv run gdoc2netcfg password <query>        # Look up device password by hostname/MAC/IP
uv run gdoc2netcfg password --type snmp <query>  # Look up SNMP community string
uv run gdoc2netcfg password --type ipmi <query>  # Look up IPMI credentials
uv run gdoc2netcfg password --quiet <query>      # Output password only (for piping)
uv run gdoc2netcfg tasmota scan --force    # Scan IoT VLAN for Tasmota devices
uv run gdoc2netcfg tasmota show            # Show cached Tasmota device data
uv run gdoc2netcfg tasmota configure --dry-run --all  # Preview config changes
uv run gdoc2netcfg tasmota configure <host>      # Push config to a specific device
uv run gdoc2netcfg tasmota ha-status       # Check Home Assistant integration
uv run gdoc2netcfg zigbee scan --force     # Scan Zigbee2MQTT sites via MQTT
uv run gdoc2netcfg zigbee show             # Show cached Zigbee device data
uv run gdoc2netcfg zigbee update-sheet --dry-run  # Preview Zigbee sheet updates
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
Generators (generators/)    Output: dnsmasq_leaf, pdns_internal, pdns_external,
    │                        recursor_forward (welland DNS stack);
    │                        dnsmasq_internal, dnsmasq_external (legacy, monarto);
    │                        nagios, nginx, letsencrypt, topology (Graphviz DOT)
    │
Config files               Per-host .conf files in output directories
```

Supporting modules:
- `utils/` — shared helpers: IP sort/classification (`ip.py`), DNS/path injection guards (`dns.py`), terminal colours (`terminal.py`)
- `audit/` — compare spreadsheet data against live network state
- `storage/` — SQLite historical storage (`config.db` + `discovery.db`) with delta-based retention; see **SQLite Storage** below

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

Welland runs the redesigned three-scope DNS stack (see `docs/dns-naming.md`
and welland's `~/local/net/CLAUDE.md`), generated by four generators whose
output keys are deploy-relative paths so `out/` mirrors `/etc`:

- **`dnsmasq_leaf`** — per-net DHCP+DNS fragments (`etc/dnsmasq.d/<net>/generated/`),
  one dnsmasq instance per network.
- **`pdns_internal`** — the central authoritative zones (site zone with
  aggregate records + CNAME projections + insecure NS delegations, wg/transit
  zones, central + catch-all reverses) as bind-backend zone files
  (`etc/powerdns/zones-internal/` + `bind-internal.conf`).
- **`pdns_external`** — the public zone (`etc/powerdns/zones-external/`);
  RFC 1918 v4 maps to the site's public IPv4, v6 stays real; CGNAT excluded;
  `extra_zones` references hand-maintained publicly-delegated zones.
- **`recursor_forward`** — the pdns-recursor routing table
  (`forward-zones.yml`): leaf nets → their gateways (`recurse: true` —
  dnsmasq is not a clean auth), central zones → `127.0.0.1:5300`, delegated
  nets (fpgas → tweed) and `peer_zones` knob for cross-site + vanity zones.

SOA serials = newest input-data change-time (sheet CSV/toml mtimes + last
data-changing SSHFP scan) + the code's git-describe number — zone files only
change when their inputs do. Deploys must run WITHOUT `--force` (validators
gate).

The legacy `dnsmasq_internal`/`dnsmasq_external` generators produce the old
single-instance split-horizon config and remain in use on **monarto only**
until its migration; both share record generation via `dnsmasq_common.py`.

### Let's Encrypt Certificates

The letsencrypt generator (`letsencrypt.py`) produces per-host certbot scripts in `certs-available/{primary_fqdn}` and a `renew-enabled.sh` orchestrator, using DNS-01 challenge validation. On **welland** the live renewal configs use `/opt/certbot/bin/certbot-hook-pdns` (`auth-hook`/`cleanup-hook`), which edits the pdns@external bind-backend zone file directly (pdnsutil record edits are SQL-backend-only), bumps the SOA serial, reloads, NOTIFYs the Rollernet secondaries, and waits until the TXT is visible on ns1.rollernet.us before returning. NOTE: the generator's emitted scripts still reference the legacy `certbot-hook-dnsmasq` CLI (correct for monarto; a welland-side gap for NEWLY-created certs — existing renewals are rewired). Deploy hooks are added based on `hardware_type` (e.g. supermicro-bmc, netgear-switch). Only public FQDNs (`is_fqdn=True`) are included as `-d` domains.

### Nginx Reverse Proxy

The nginx generator (`nginx.py`) produces per-host config directories under `sites-available/{fqdn}/`. Each host gets three files: `http-proxy.conf` (HTTP reverse proxy on port 80), `https-upstream.conf` (stream upstream for TLS passthrough), and `https-map.conf` (SNI map entries). Multi-interface hosts additionally get `http-healthcheck.lua`, `https-healthcheck.lua`, and `https-balancer.lua` in their directory.

HTTPS is handled via stream SNI passthrough rather than http-module HTTPS blocks, ensuring consistent TLS behaviour for both IPv4 (proxied) and IPv6 (direct) paths. HTTP blocks include inline ACME challenge locations with `try_files` fallback to the backend for hosts handling their own ACME challenges.

Multi-interface hosts get a combined HTTP config file containing an `upstream` block listing all interface IPs for round-robin failover with `proxy_next_upstream`, a root server block using the upstream, and per-interface server blocks with direct `proxy_pass`. Their HTTPS upstream uses `balancer_by_lua_file` for health-aware peer selection via a custom Lua HTTPS health checker (`scripts/checker.lua`). Single-interface hosts produce simple direct `proxy_pass` configs and direct stream server entries.

All generated files live under a single deployment root (`gdoc2netcfg_dir`, default `/etc/nginx/gdoc2netcfg/`). Enabling a host is a single symlink: `ln -s /etc/nginx/gdoc2netcfg/sites-available/{fqdn} /etc/nginx/sites-enabled/{fqdn}`. Removing all generated configs is `rm -rf /etc/nginx/gdoc2netcfg`.

### Network Topology

The topology generator (`topology.py`) produces a Graphviz DOT diagram of the physical network from bridge supplement data. Switch nodes (hosts with bridge data) are boxes; host nodes (whose MACs appear in switch MAC tables) are ellipses. LLDP-learned edges are bold and bidirectional; MAC-learned edges are dashed. Locally administered MACs are filtered out.

### Configuration

`gdoc2netcfg.toml` (gitignored, site-specific) defines site topology (domain, VLANs, IPv6 prefixes, network subdomains), sheet URLs, cache directory, and generator settings. Loaded by `config.py` into a `PipelineConfig` dataclass containing a `Site` object.

`gdoc2netcfg.toml.example` is the tracked template with Welland defaults. Each site copies it to `gdoc2netcfg.toml` and edits the `[site]`, `[ipv6]`, `[generators] enabled`, and `[[zigbee.sites]]` sections. This avoids merge conflicts when deploying to Monarto.

### SQLite Storage

Supplement and spreadsheet data are stored in two SQLite databases under the cache directory (`storage/` modules):

- `.cache/config.db` (`ConfigDB`) — spreadsheet data: CSV snapshots, device records, VLAN definitions (scan_type `csv_fetch`).
- `.cache/discovery.db` (`DiscoveryDB`) — supplement scan results: reachability, SSH host keys, SSL certs, BMC firmware, SNMP, bridge, NSDP, Tasmota, Zigbee (one scan_type each).
- `.cache/credentials.db` (`CredentialsDB`) — **root-only (`0600`)** store of the device credential columns (`Password`, `SNMP Community`, `IPMI Username`, `IPMI Password`), stripped out of the world-readable cache at fetch time. Written only by `fetch`; read only by the `password` command. EAV `(hostname, field, value)`, delta-stored with NULL tombstones (scan_type `csv_credentials`). `fetch` **fails loudly (storing and caching nothing)** when a filled credential cell sits on a spreadsheet row whose value cannot reach the store — a row the host builder discards (no MAC+IP) or a non-first interface row of its machine (`find_lost_credential_cells` in `derivations/host_builder.py`); the fix is moving the cell onto the machine's primary MAC+IP row.

Both inherit `BaseDatabase` (`storage/base.py`): DELETE journal mode, schema versioning (upgrade steps may be DDL strings or Python callables for data migrations), and a shared `scans` audit table (one row per scan/fetch). All supplement data lives in **typed, structured tables** (no JSON blobs) — deeply nested documents are exploded into per-field tables driven by shared specs (`_BRIDGE_DOC_FIELDS` etc.) so DDL, validation, insertion, and reconstruction cannot drift. Storage is **delta-based at the finest stable key** (host, switch, device, zigbee device/site-bridge) — rows are INSERTed only for an entity whose values actually changed, so history accrues with bounded growth; reads reconstruct the latest state via `load_latest_*`. Saves validate document shapes strictly and fail loud on drift.

**`discovery.db` is the sole source for supplement data.** Supplement scans take their last-known baseline from the DB and the CLI persists results back to the DB only — the flat supplement `.json` caches are neither read nor written. `_build_pipeline` and the show/publish commands load supplements via `load_latest_*` (a supplement with no completed scan contributes no enrichment). Scan freshness is the age of the latest completed scan per scan_type (`scans` table, 5-minute window) instead of file mtimes. `cmd_fetch` still writes the CSVs to both the flat cache (the parser input) and `config.db`. The DBs are created automatically on first write (daemon, scan commands, fetch); inspect with `db info` / `db history`.

> **Journal mode:** the DBs use `journal_mode=DELETE` (not WAL), so a read-only open (`mode=ro` URI) needs no write access at all — a non-root user can read the root-owned production DBs. Writes serialize against reads; a 5s `busy_timeout` absorbs the contention.

### Models

- `MACAddress`, `IPv4Address`, `IPv6Address` — frozen, validated, normalized value types in `models/addressing.py`
- `Host` — groups `NetworkInterface` entries for one machine, with default IP selection; `VirtualInterface` for derived interfaces
- `NetworkInventory` — the complete enriched model passed to generators
- `VLAN`, `Site` — network topology definitions in `models/network.py`, loaded from config + VLAN Allocations sheet
- `PortLinkStatus`, `PortTrafficStats`, `SwitchData`, `SwitchDataSource` — unified switch data model in `models/switch_data.py`, populated from SNMP or NSDP sources

**Credential columns**: The spreadsheet may include extra columns such as `Password`, `SNMP Community`, `IPMI Username`, `IPMI Password`. These are **stripped from the world-readable cache at fetch time** and stored in the root-only `.cache/credentials.db` (see *SQLite Storage*) — they are NOT present in `Host.extra` from the cache. The `password` CLI command merges them transiently from the store onto the matched host before resolving the requested field (and so must run as root). Non-credential extra columns remain in `Host.extra` as normal.

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
| welland | `ten64.welland.mithis.com` (10.1.10.1) | `10.1.X.X` | `2404:e80:a137:1XX::` | internal, external, nginx, known_hosts (+ nagios, currently unused) |
| monarto | `ten64.monarto.mithis.com` (10.2.10.1) | `10.2.X.X` | `2404:e80:a137:2XX::` | internal, external, nginx |

Both sites share the same Google Spreadsheet. The spreadsheet uses `10.X.Y.Z` (literal `X` in the second octet) for devices that exist at multiple sites, and a "Site" column to restrict records to a specific site. The `site_octet` in each site's `gdoc2netcfg.toml` replaces the `X` placeholder.

Both sites are externally accessible (each sets its own `public_ipv4`) and run split-horizon DNS plus an nginx reverse proxy — but on DIFFERENT stacks: **welland** runs the redesigned per-net-leaf + pdns architecture (recursor on 10.1.0.1, pdns@internal auth on 127.0.0.1:5300, pdns@external public, DNSSEC signed); **monarto** still runs the legacy single-instance dnsmasq@internal/@external pair until its migration. The other differences: welland additionally enables the `letsencrypt` generator (per-host DNS-01 certs) and `known_hosts`, whereas monarto manages its TLS certs with **certbot directly**. Welland's config also lists the `nagios` generator, but it is **currently unused** — nothing consumes its `nagios-switches.cfg` output.

### Deploying code changes

Use SSH agent forwarding and `sudo -E` so that `git pull` can authenticate via the forwarded SSH key:

```bash
# Welland
ssh -A ten64.welland.mithis.com "cd /opt/gdoc2netcfg && sudo -E git pull"

# Monarto (via WireGuard tunnel; resolves to 10.2.x, routed through the
# tunnel — the tunnel endpoint 10.98.2.2 also works)
ssh -o ControlPath=none -o ForwardAgent=yes tim@ten64.monarto.mithis.com \
  "cd /opt/gdoc2netcfg && sudo -E git pull"
```

`git pull` is clean on both sites — `gdoc2netcfg.toml` is gitignored, so each site's local config is never touched by pulls. After pulling changes that affect MQTT publishing (`mqtt_ha.py`), restart the reachability daemon:

```bash
sudo systemctl restart gdoc2netcfg-reachability.service
```

If a site doesn't have a local config yet, create one after pulling:

```bash
cp gdoc2netcfg.toml.example gdoc2netcfg.toml
# Edit [site], [ipv6], [generators] enabled, and [[zigbee.sites]] for this site
```

Note: `uv` on monarto is at `~/.local/bin/uv` (not in PATH for non-interactive shells).

### SQLite databases

The SQLite DBs (`.cache/config.db`, `.cache/discovery.db`) accrue historical scan data (see *SQLite Storage*). They are created automatically by the first write (the reachability daemon, a scan command, or `fetch`). Inspect from the repo dir (the cache path is resolved relative to the working directory):

```bash
cd /opt/gdoc2netcfg && .venv/bin/gdoc2netcfg db info   # sudo-free (read-only)
```

**Ownership: root writes, anyone reads.** The reachability daemon runs as root, so `/opt/gdoc2netcfg/.cache` and `.venv` are owned by `root`. Reads are sudo-free — the DBs use DELETE journal and read-only opens (see *Journal mode* under *SQLite Storage*), so commands that only read (`generate`, `validate`, `password`, `db info`, `db history`, the show commands) work as a normal user. Commands that **write** the DBs (the supplement scan commands, `fetch`) must run via `sudo`, using the direct `.venv/bin/gdoc2netcfg` (not `uv run`, which would re-sync the root-owned venv). The reachability daemon writes a new `reachability` scan to `discovery.db` each 5-minute cycle; the other supplements only gain history when their scan commands are run.

### DNS deployment

#### Welland (current architecture)

One dnsmasq **leaf** per network (`dnsmasq@guest|tmp|sm|pwr|store|net|wifi|iot|roam|int`,
plus `dnsmasq@tfpgas` as a port=0 DHCP/PXE-only instance), a central
**pdns-recursor** (10.1.0.1 + 2404:e80:a137:100::1 + 127.0.0.1 + wg/tfpgas
listens), **pdns@internal** (127.0.0.1:5300, bind backend, the central signed
zones), and **pdns@external** (public, signed, hidden primary for the
Rollernet secondaries — `query-local-address` pinned to the registered
primary IP or their NOTIFY ACL refuses).

```
/etc/dnsmasq.d/
  dnsmasq.<net>.conf             # per-leaf entry: conf-dir=shared, adblock (roam/int only), <net>, <net>/generated
  shared/                        # base, logging, edns
  adblock/adblock.conf           # local=/domain/ blocklist — roam + int leaves ONLY
  <net>/                         # 00-listen, 01-upstream, 02-dns, 03-dhcp (+05-pxe on PXE nets)
  <net>/generated/               # ← gdoc2netcfg dnsmasq_leaf output (wipe-and-replace safe)
/etc/powerdns/
  recursor.d/10-welland-central.yml   # listens, forward-zones file, DNSSEC + trust anchor + NTAs
  forward-zones.yml                   # ← recursor_forward output
  pdns-internal.conf / pdns-external.conf
  bind-internal.conf / bind-external.conf   # ← generator output
  zones-internal/                     # ← pdns_internal output + welland.mithis.com.extra (hand records)
  zones-external/                     # ← pdns_external output + .extra + hand extra_zones files
```

Leaf template invariants (hard-won; see the dns-redesign verification log):
`auth-server` WITHOUT an interface arg (auth mode on the only interface
REFUSES clients' external queries); owned subnets on the FORWARD
`auth-zone` line (separate arpa auth-zones serve no PTRs);
`local=/zone/` scoping on every served zone (misses loop via the
recursor otherwise); `enable-tftp=br-<net>` (bare form binds nothing under
`except-interface=lo`); `bind-dynamic` everywhere (shared :67).

```bash
# Welland fetch + generate + deploy:
cd /opt/gdoc2netcfg
sudo /usr/local/bin/uv run gdoc2netcfg fetch
sudo /usr/local/bin/uv run gdoc2netcfg validate      # must be 0 errors — NEVER deploy with --force
sudo /usr/local/bin/uv run gdoc2netcfg generate dnsmasq_leaf pdns_internal pdns_external recursor_forward --output-dir out
# out/etc mirrors /etc — copy the changed files, e.g.:
sudo cp out/etc/dnsmasq.d/<net>/generated/*.conf /etc/dnsmasq.d/<net>/generated/
sudo cp out/etc/powerdns/zones-internal/*.zone /etc/powerdns/zones-internal/
sudo cp out/etc/powerdns/forward-zones.yml /etc/powerdns/
sudo systemctl restart dnsmasq@<net>     # only the touched leaves
sudo pdns_control --config-name=internal --socket-dir=/var/run/pdns-internal bind-reload-now
sudo systemctl restart pdns-recursor     # if forward-zones.yml changed
```

#### Monarto (legacy, until its migration)

Monarto still runs the old split-horizon pair (`dnsmasq@internal`,
`dnsmasq@external`) fed by the `dnsmasq_internal`/`dnsmasq_external`
generators: entry points `dnsmasq.{instance}.conf`, hand config in
`internal/`+`external/`, generated per-host files in `*/generated/`
(wipe-and-replace: `sudo rm -f .../generated/*.conf && sudo cp ...`).

Each `make deploy-*` target also records its `/etc` change in etckeeper's git
via `scripts/etckeeper_commit.py` — a **path-scoped** commit (only that
target's `/etc` path, never `etckeeper commit`/`git add -A`, so unrelated
in-flight `/etc` edits are not bundled) with message
`gdoc2netcfg deploy <component>: <git-describe>`. A path with no changes is a
no-op; a failed commit aborts the deploy.

#### Cross-site DNS forwarding

The two sites forward DNS queries to each other via the WireGuard tunnel (`10.98.2.1` welland, `10.98.2.2` monarto, a `10.98.2.0/30`). On welland this is the recursor's `peer_zones` knob in `gdoc2netcfg.toml` (`monarto.mithis.com` + monarto's reverse zones → `10.98.2.2`, `recurse: true`; flips to monarto's own central `10.2.0.1` when monarto migrates). On monarto it is still dnsmasq `server=` directives in `03-zone-forwarders.conf`.

### nginx

Generated nginx configs are deployed to `/etc/nginx/gdoc2netcfg/` (per-host directories under `sites-available/`, plus `scripts/`, `conf.d/`, `stream.d/` for healthcheck infrastructure). Hosts are activated via symlinks: `ln -s /etc/nginx/gdoc2netcfg/sites-available/{fqdn} /etc/nginx/sites-enabled/{fqdn}`. Deployed on **both sites** (welland and monarto).

### Tasmota remote syslog

Tasmota devices send their logs (UDP syslog) to the site router. The
rsyslog drop-in (`etc/rsyslog-tasmota.conf` → `/etc/rsyslog.d/tasmota.conf`)
receives on UDP 514 into per-device files `/var/log/tasmota/<hostname>.log`
(rotated daily, 14 kept — `etc/logrotate-tasmota`). Deploy both with
`sudo make deploy-syslog` (path-scoped etckeeper commit included).

Device-side settings are pushed by `tasmota configure`: `[tasmota]
syslog_host` names the sink by sheet hostname and is resolved to the
sink's IP on each device's VLAN from inventory data (never DNS);
`syslog_level` (default 2) can be overridden per device via the sheet's
"Syslog Level" column (0 silences one device). Empty `syslog_host`
disables the feature (monarto until it opts in).

The Tasmota scan data adds three columns to `discovery.db` (schema
v9). The first write after pulling this change applies the migration
automatically — but as with other heavyweight upgrades, stop
`gdoc2netcfg-reachability.service` first and restart it afterwards, to
avoid the known crash-loop gotcha where the daemon hits the DB mid
schema-upgrade.

### Let's Encrypt

Certbot scripts are generated to `/opt/gdoc2netcfg/letsencrypt/`. The `letsencrypt` **generator** is Welland only — monarto does not enable it; monarto's TLS certs (`/etc/letsencrypt/live/ten64.monarto.mithis.com`, `ipv6-ten64.monarto`) are managed by **certbot directly** (a single host cert that nginx terminates with), not by this per-host DNS-01 generator.

```bash
sudo uv run gdoc2netcfg generate --output-dir /opt/gdoc2netcfg letsencrypt
sudo sh /opt/gdoc2netcfg/letsencrypt/certs-available/{fqdn}  # Provision a cert
```

The auth hook is the `certbot-hook-dnsmasq` Python CLI installed at `/opt/certbot/bin/certbot-hook-dnsmasq` (separate repo: `mithro/certbot-hook-dnsmasq`). It creates TXT records in the external dnsmasq, verifies local resolution, sends NOTIFY to secondaries, and polls until they sync.

### Looking up device credentials

On either site, look up credentials from the cached spreadsheet data:

```bash
cd /opt/gdoc2netcfg
sudo .venv/bin/gdoc2netcfg password switch1              # Password for switch1
sudo .venv/bin/gdoc2netcfg password --quiet 10.1.10.1    # Password only (pipe to clipboard etc.)
sudo .venv/bin/gdoc2netcfg password --type snmp switch1   # SNMP community string
sudo .venv/bin/gdoc2netcfg password --type ipmi bmc.server1  # IPMI username + password
```

Credentials are stored root-only in `.cache/credentials.db`, so the `password` command must run as **root** on prod (`sudo .venv/bin/gdoc2netcfg password <query>`, not `uv run`). It reads the host inventory from the credential-free CSV cache and the secret from `credentials.db` (`gdoc2netcfg fetch` must have been run at least once); it does not contact the Google Sheet directly. `generate`, `db`, `validate`, and the show commands stay sudo-free — the rest of the cache is credential-free. A `password --field <non-credential-column>` lookup also stays sudo-free (it never opens the credential store).

### Other

SSH host keys live in `discovery.db` (scan_type `ssh_host_keys`). SSHFP records are derived from these keys at runtime.
