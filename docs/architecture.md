# Architecture

`gdoc2netcfg` is a six-stage data pipeline that transforms Google Spreadsheet device records into network infrastructure configuration files.

## Pipeline stages

```
Sources (sources/)          Fetch CSV from Google Sheets, cache locally, parse into DeviceRecord
    │                        Also parses VLAN Allocations sheet (vlan_parser.py)
Derivations (derivations/)  Pure functions: IPv4→IPv6, IP→VLAN, hostname, DHCP name, DNS names,
    │                        default IP, hardware type detection, site IP remapping
    │                        host_builder.py orchestrates these into Host objects
Supplements (supplements/)  External enrichment (all cached to .cache/):
    │                        SSHFP (ssh-keyscan), SSL certs, SNMP host info, SNMP bridge/topology,
    │                        BMC firmware (ipmitool), NSDP switch discovery, reachability (ping),
    │                        Tasmota IoT device status, MQTT HA publishing
Constraints (constraints/)  Validation: field presence, BMC placement, MAC uniqueness,
    │                        IPv6 consistency, bridge/topology, SNMP availability, SSL certs
Generators (generators/)    Output: dnsmasq_internal, dnsmasq_external, nagios, nginx,
    │                        letsencrypt, topology (Graphviz DOT), known_hosts
Config files                Per-host .conf files in output directories
```

## Data flow

1. `sources/parser.py` parses CSV rows into `DeviceRecord` (machine, mac, ip, interface)
2. `derivations/host_builder.py::build_hosts()` groups records by machine name into `Host` objects, each with multiple `NetworkInterface` entries
3. `derivations/dns_names.py::derive_all_dns_names()` computes all DNS name variants per host (hostname, interface, subdomain, ipv4/ipv6 prefix variants)
4. `build_inventory()` creates `NetworkInventory` with precomputed `ip_to_hostname` and `ip_to_macs` indexes
5. Generators consume `NetworkInventory` to produce config files

## Key models

All models live in `src/gdoc2netcfg/models/`:

- **`MACAddress`, `IPv4Address`, `IPv6Address`** -- frozen, validated, normalised value types (`models/addressing.py`)
- **`NetworkInterface`** -- a single physical interface on a host (MAC, IPv4, IPv6 addresses, VLAN, DHCP name)
- **`VirtualInterface`** -- logical endpoint grouping physical NICs sharing an IP (for multi-homed hosts)
- **`Host`** -- groups `NetworkInterface` entries for one machine, with default IP, DNS names, SSHFP records, supplement data (SNMP, bridge, NSDP, Tasmota, BMC firmware, SSL certs)
- **`NetworkInventory`** -- the complete enriched model passed to generators, with precomputed lookup indexes
- **`Site`** -- site topology (domain, VLANs, IPv6 prefixes, network subdomains)
- **`SwitchData`** -- unified switch data model (SNMP + NSDP), with MAC tables, port status, LLDP, PoE

## BMC handling

BMCs (Baseboard Management Controllers) are physically separate machines attached to a primary host. When a spreadsheet row has `interface="bmc"` on `machine="big-storage"`, `build_hosts()` creates a separate host `bmc.big-storage` -- not a sub-interface. The BMC gets its own hostname, DNS records, DHCP binding, and PTR entry.

## IPv4 to IPv6 mapping

Dual-stack addressing uses the scheme:

```
10.AA.BB.CCC  →  {prefix}AABB::CCC
```

Where `AA` is unpadded and `BB` is zero-padded to 2 digits. Prefixes are configured in `gdoc2netcfg.toml` under `[ipv6]`. See [ipv4-to-ipv6.md](ipv4-to-ipv6.md) for the full specification.

## Split-horizon DNS

The dnsmasq generator has internal and external variants:

- **Internal** (`dnsmasq.py`) -- produces DHCP bindings, PTR records, forward DNS records, CAA records, and SSHFP records using internal RFC 1918 addresses
- **External** (`dnsmasq_external.py`) -- replaces RFC 1918 IPs with the site's public IPv4 address for external-facing DNS. Does not emit DHCP or PTR records (internal IPs aren't routable externally)

Both generators produce per-host `.conf` files (one file per host).

## Configuration

`gdoc2netcfg.toml` defines site topology (domain, VLANs, IPv6 prefixes, network subdomains), sheet URLs, cache directory, and generator settings. Loaded by `config.py` into a `PipelineConfig` dataclass containing a `Site` object.

## MQTT reachability publishing

`supplements/mqtt_ha.py` publishes host reachability to Home Assistant via MQTT discovery. Each host becomes an HA device with:

- **Host-level**: connectivity (binary_sensor), presence (device_tracker), stack mode (sensor)
- **Per-interface**: connectivity, stack mode, IPv4, MAC, RTT (sensors)

Entity IDs use `_node_id(host.hostname)` -- the hostname, not machine_name. This is critical because BMC hosts share `machine_name` with their parent (both `big-storage` and `bmc.big-storage` have `machine_name="big-storage"`), but have unique hostnames. Entity IDs include the VLAN subdomain, e.g. `gdoc2netcfg_au_plug_1_iot_connectivity`.

Discovery payloads are retained; state messages are not (expire_after handles staleness). The daemon runs as `gdoc2netcfg-reachability.service`, scanning every 5 minutes.

## Network reachability dashboard

`scripts/ha-create-reachability-dashboard.py` generates a self-contained HTML dashboard deployed to HA's `/config/www/` via SSH. Embedded in HA as a Lovelace iframe panel.

The HTML bakes in structural data (host list, entity ID prefixes, FQDNs, PoE mappings) and connects to HA's WebSocket API at runtime for live entity states. The dashboard only needs regeneration when the network structure changes (new hosts, PoE remapping), not for status updates.

Features: sortable columns (natural sort), fold/unfold multi-interface hosts, live Tasmota/PoE control state, dark/light theme from HA.

Files: `scripts/ha-create-reachability-dashboard.py` (generator), `scripts/ha-reachability-dashboard.html` (template).

## Source layout

```
src/gdoc2netcfg/
├── cli/            CLI entry point and subcommands
├── config.py       TOML config loader
├── models/         Data models (addressing, host, network, switch_data)
├── sources/        CSV fetching, caching, parsing, VLAN allocations
├── derivations/    Pure derivation functions (IPv6, VLAN, hostname, DNS)
├── supplements/    External data enrichment (SSHFP, SSL, SNMP, NSDP,
│                   reachability, Tasmota, BMC firmware, MQTT HA publishing)
├── constraints/    Validation checks
├── generators/     Output generators (dnsmasq, nagios, nginx, letsencrypt,
│                   topology, known_hosts)
├── utils/          Shared utilities (IP helpers, DNS utils, terminal colours)
└── audit/          Compare spreadsheet data against live network state

scripts/
├── ha-create-reachability-dashboard.py   Dashboard generator + deployer
└── ha-reachability-dashboard.html        Dashboard HTML/JS/CSS template
```
