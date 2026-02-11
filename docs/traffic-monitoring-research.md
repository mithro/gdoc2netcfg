# Traffic Monitoring Research

## Goal

Add a generator to gdoc2netcfg that produces configuration for a traffic
monitoring system, so all known hosts, switches, and BMCs get their network
interfaces monitored automatically from the same Google Spreadsheet source of
truth.

## Monitoring Scenarios

There are four distinct device classes that need traffic monitoring, each with
different data collection mechanisms:

| Scenario | Devices | Data Source | What's Available Today |
|---|---|---|---|
| **Local host** | The Ten64 running gdoc2netcfg | `/proc/net/dev` kernel counters | Not collected |
| **SNMP switches** | Managed Netgear, Cisco | IF-MIB via SNMPv2c | Already collected: `ifHCInOctets`, `ifHCOutOctets`, `ifInErrors` (in bridge supplement) |
| **NSDP switches** | Netgear Plus/unmanaged | NSDP protocol (proprietary) | Already collected: `PortStatistics` (bytes_rx, bytes_tx, crc_errors) |
| **BMCs** | Supermicro IPMI | SNMP (X10+) or IPMI LAN | `bmc_firmware_info.snmp_capable` known; traffic not yet collected |

### What gdoc2netcfg Already Knows Per Host

A generator receives `NetworkInventory` containing every host with:

- IP addresses (IPv4 + IPv6), MAC addresses, hostnames, FQDNs
- SNMP community strings (`host.extra["SNMP Community"]`)
- Hardware type classification (`host.hardware_type`: `netgear-switch`, `cisco-switch`, `supermicro-bmc`, etc.)
- Per-switch interface names and ifIndex values (from `host.switch_data`)
- NSDP-discovered switch model, port count, port statistics (from `host.nsdp_data`)
- BMC firmware info including SNMP capability (from `host.bmc_firmware_info`)
- Site info (domain, VLANs, IPv6 prefixes)

---

## Tool Evaluation

### Comparison Matrix

| Tool | Config Gen Fit | SNMP Quality | ARM64 | RAM | Alerting | All 4 Scenarios |
|---|---|---|---|---|---|---|
| **Prometheus + SNMP Exporter** | Excellent | Excellent | Yes | ~500MB-1GB | Excellent | Yes |
| **Telegraf + InfluxDB** | Good | Very good | Partial | ~1-1.5GB | Good | Yes |
| **Collectd** | Fair | Good | Yes | ~30MB | Basic | Partial |
| **Cacti** | Poor (DB) | Excellent | Heavy | ~500MB-1GB | Basic | No |
| **LibreNMS** | Poor (DB) | Best | Untested | 2GB+ | Good | Partial |
| **Zabbix** | Moderate (XML) | Excellent | Heavy | 2-4GB | Best | Yes |
| **MRTG** | Excellent | Basic (v1/v2c) | Yes | ~20MB | None | Partial |
| **Netdata** | Good | Good | Yes | ~200MB | Good | Partial |
| **vnStat** | N/A | None | Yes | ~5MB | None | Local only |

### Detailed Analysis

#### Prometheus + SNMP Exporter + Grafana (Recommended)

**Why it fits best:**

1. **`file_sd_configs` is a perfect match for gdoc2netcfg's generator pattern.**
   Prometheus watches JSON files listing scrape targets with labels. The
   generator produces a few JSON files (one per device class), and Prometheus
   picks up changes automatically without restart. No database, no API calls —
   just files.

2. **Covers all four scenarios with dedicated exporters:**
   - Local host: `node_exporter` (single Go binary, ~10MB RAM, zero config)
   - SNMP switches: `snmp_exporter` with IF-MIB module
   - NSDP switches: Custom Python exporter using existing `src/nsdp/` library + `prometheus_client`
   - BMCs: `snmp_exporter` for SNMP-capable (X10+), `ipmi_exporter` for older

3. **Lightweight enough for Ten64.** All components have official arm64
   binaries. Full stack runs in ~500MB-1GB RAM.

4. **Production-grade alerting.** Prometheus Alertmanager handles dedup,
   silencing, routing to email/Slack/PagerDuty.

5. **Best visualization.** Grafana is industry standard for network dashboards.

**Config generation output:**

```
prometheus/
  targets/
    switches_snmp.json     # SNMP targets for managed switches
    switches_nsdp.json     # Targets for NSDP-only Netgear switches
    bmcs.json              # SNMP/IPMI targets for BMCs
    servers.json           # node_exporter targets for Linux hosts
  alerts/
    interface_alerts.yml   # PromQL alert rules
```

Each target file follows `file_sd_configs` format:

```json
[
  {
    "targets": ["10.1.5.1"],
    "labels": {
      "hostname": "switch1.welland.mithis.com",
      "hardware_type": "netgear-switch",
      "site": "welland",
      "__param_module": "if_mib"
    }
  }
]
```

**Components to deploy:**

| Component | Binary | Purpose | ARM64 | RAM |
|---|---|---|---|---|
| Prometheus | `prometheus` | Time-series DB + scraper | Official | ~200-400MB |
| SNMP Exporter | `snmp_exporter` | SNMP → Prometheus metrics | Official | ~20MB |
| node_exporter | `node_exporter` | Local host metrics | Official | ~10MB |
| ipmi_exporter | `ipmi_exporter` | BMC metrics via freeipmi | Official | ~10MB |
| Grafana | `grafana-server` | Dashboards | Official | ~200-500MB |
| NSDP exporter | Custom Python | NSDP → Prometheus metrics | Python | ~30MB |

#### Telegraf + InfluxDB + Grafana

**Pros:** Good SNMP plugin, built-in IPMI support, TOML `conf.d` directory.

**Cons:** InfluxDB 3.x went proprietary — risky long-term bet. Config is more
verbose (each SNMP target needs its own `[[inputs.snmp]]` block with repeated
OID definitions vs Prometheus' module-based approach). Higher RAM (~1.5GB).

#### MRTG (Simple Alternative)

**Pros:** Trivially simple config generation. Near-zero resources (runs via
cron). Produces static HTML+PNG served by existing nginx.

**Cons:** SNMPv2c only, no interactive dashboards, no alerting, no NSDP/BMC
support. Could be a "phase 0" while Prometheus is set up.

#### Not Recommended

- **Cacti, LibreNMS, Observium**: Database-driven config models fundamentally
  conflict with gdoc2netcfg's file-generation pattern. Too heavy for Ten64.
- **Zabbix**: Excellent but 2-4GB RAM; XML import format is complex.
- **Collectd**: Declining community, awkward config syntax.
- **vnStat**: Local-only, no SNMP, no alerting.
- **Netdata**: Good for local monitoring but SNMP support less mature than
  Prometheus SNMP Exporter.

---

## Recommended Architecture: Prometheus Stack

### Generator Design

The generator fits naturally into gdoc2netcfg's existing patterns:

```python
def generate_prometheus(inventory: NetworkInventory) -> dict[str, str]:
    """Generate Prometheus monitoring configuration.

    Returns dict mapping relative file paths to content:
      targets/switches_snmp.json  - SNMP switch targets
      targets/switches_nsdp.json  - NSDP switch targets
      targets/bmcs.json           - BMC targets
      targets/servers.json        - Server/host targets
      alerts/interface_alerts.yml - Alert rules
    """
```

**Classification logic** (uses data already in the model):

```
for host in inventory.hosts_sorted():
    if host.hardware_type in ("netgear-switch", "cisco-switch"):
        → switches_snmp.json (module: if_mib)
    elif host.hardware_type == "netgear-switch-plus":
        → switches_nsdp.json (module: nsdp, custom exporter)
    elif host.hardware_type == "supermicro-bmc":
        if host.bmc_firmware_info and host.bmc_firmware_info.snmp_capable:
            → bmcs.json (module: bmc_snmp)
        else:
            → bmcs.json (module: ipmi)
    else:
        → servers.json (node_exporter target)
```

### SNMP Exporter Modules

The `snmp.yml` config defines reusable modules (written once, not per-host):

| Module | MIBs | Metrics |
|---|---|---|
| `if_mib` | IF-MIB, IF-MIB (HC) | `ifHCInOctets`, `ifHCOutOctets`, `ifInErrors`, `ifOutErrors`, `ifOperStatus`, `ifHighSpeed`, `ifName` |
| `system_mib` | SNMPv2-MIB | `sysDescr`, `sysName`, `sysUpTime` |
| `bmc_snmp` | IF-MIB + HOST-RESOURCES-MIB | Interface + system metrics for SNMP-capable BMCs |
| `bridge_mib` | Q-BRIDGE-MIB | VLAN info, MAC table (for topology enrichment) |

### Custom NSDP Exporter

A small Python service (~100 lines) using:
- The existing `src/nsdp/` library (already in this repo)
- `prometheus_client` package for exposition

Exposes metrics like:
```
nsdp_port_bytes_received{hostname="gs108e-1",port="1"} 123456789
nsdp_port_bytes_sent{hostname="gs108e-1",port="1"} 987654321
nsdp_port_crc_errors{hostname="gs108e-1",port="1"} 0
```

### Alert Rules

The generator can produce PromQL alert rules:

```yaml
groups:
  - name: interface_alerts
    rules:
      - alert: SwitchPortDown
        expr: ifOperStatus{job="snmp"} != 1
        for: 5m
        labels:
          severity: warning

      - alert: HighErrorRate
        expr: rate(ifInErrors{job="snmp"}[5m]) > 1
        for: 10m
        labels:
          severity: critical

      - alert: BMCUnreachable
        expr: up{job="bmc"} == 0
        for: 10m
        labels:
          severity: warning
```

### Deployment

On each site (welland/monarto):

```bash
# Generate monitoring config
cd /opt/gdoc2netcfg
uv run gdoc2netcfg generate prometheus

# Deploy target files (Prometheus watches these, no restart needed)
sudo cp -r prometheus/targets/ /etc/prometheus/file_sd/
sudo cp prometheus/alerts/* /etc/prometheus/rules/

# Prometheus reloads automatically via file_sd_configs
# Alert rules need a reload signal:
sudo systemctl reload prometheus
```

### TOML Configuration

```toml
[generators.prometheus]
output_dir = "prometheus"
prometheus_url = "http://localhost:9090"
snmp_exporter_url = "http://localhost:9116"
nsdp_exporter_url = "http://localhost:9117"
node_exporter_port = "9100"
```

---

## Open Questions

1. **NSDP exporter**: Should this live in the gdoc2netcfg repo (it already has
   the NSDP library) or be a separate project?

2. **Grafana dashboards**: Should the generator also produce provisioned Grafana
   dashboard JSON? Or is that manual setup?

3. **Per-site differences**: Welland has external DNS + nginx + nagios. Monarto
   is internal only. Should monitoring scope differ per site?

4. **Credential handling**: Prometheus SNMP Exporter can receive community
   strings via `auth` modules. Should the generator embed credentials in the
   snmp.yml, or use environment variables / secrets?

5. **Existing Nagios**: The Nagios generator already monitors switches. Should
   Prometheus replace Nagios, complement it, or is Nagios retained for
   alerting while Prometheus handles metrics/graphing?

6. **MRTG as phase 0**: Would a simpler MRTG generator be useful as a quick win
   before the full Prometheus stack?
