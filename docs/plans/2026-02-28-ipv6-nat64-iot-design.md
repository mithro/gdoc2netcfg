# IPv6 NAT64 for IoT Devices

**Date:** 2026-02-28
**Status:** Approved

## Problem

Many IoT devices (ESP32-based Tasmota plugs, RF bridges, smart switches, etc.)
do not support IPv6. Currently, gdoc2netcfg derives IPv6 addresses for all
devices indiscriminately and includes them in DHCP bindings and DNS records.
This is incorrect — IPv6-incapable devices can't use these addresses.

We want IPv6 clients to still reach these devices transparently via their
derived IPv6 addresses, using the site gateway (ten64) as a NAT64 proxy.

## Solution Overview

1. **Detect** which devices lack IPv6 support (MAC OUI + Hardware column regex)
2. **Keep** IPv6 addresses in DNS (AAAA records) so IPv6 clients can resolve them
3. **Remove** IPv6 from DHCP bindings (device can't use them)
4. **Deploy TAYGA** (userspace NAT64) on ten64 to translate IPv6→IPv4 for these
   devices, using RFC 6598 (100.64.0.0/10) as the source address range
5. **Generate** TAYGA config, systemd-networkd files, and routes from gdoc2netcfg

## Architecture

```
IPv6 client
    │
    │  dst: 2404:e80:a137:190::51 (AAAA from DNS)
    ▼
ten64 gateway
    │  Address 2404:e80:a137:190::51 is routed to nat64 TUN device
    ▼
TAYGA (nat64 TUN)
    │  Translates IPv6 → IPv4:
    │    dst: 2404:e80:a137:190::51 → 10.1.90.51
    │    src: (client IPv6) → 100.64.1.1 (TAYGA ipv4-addr)
    ▼
IoT device (10.1.90.51)
    │  Sees connection from 100.64.1.1 (recognizable as NAT64-proxied)
    │  Replies to 100.64.1.1
    ▼
ten64 gateway
    │  100.64.1.1 is local (on nat64 TUN), routes to TAYGA
    ▼
TAYGA (reverse translation)
    │  IPv4 → IPv6
    ▼
IPv6 client (receives reply)
```

## Why TAYGA over Jool

Both Jool (kernel NAT64) and TAYGA (userspace NAT64) were evaluated. TAYGA was
chosen because:

1. **No DKMS kernel module** — ten64 runs Debian sid on ARM64; kernel updates are
   frequent and DKMS rebuilds are a reliability risk
2. **Clean Netfilter coexistence** — TUN device architecture means translated
   packets traverse the normal kernel path; no conflict with existing
   iptables-nft rules from Docker/Tailscale
3. **Natural 100.64.x.x SNAT** — TAYGA's `ipv4-addr 100.64.1.1` means translated
   packets already carry a 100.64.x.x source; no separate SNAT rule needed
4. **Performance is irrelevant** — IoT traffic is minimal; TAYGA's ~200 Mbps is
   more than sufficient
5. **Trivial config generation** — one `map` line per device

### Per-host mappings required

The gdoc2netcfg address scheme (`10.AA.BB.CCC` → `{prefix}AABB::CCC`) concatenates
decimal strings into hex-interpreted IPv6 fields. For example, `10.1.90.51` →
`2404:e80:a137:190::51` where `0x190` ≠ `1.90` and `0x51` ≠ `51` in binary.
No prefix-based NAT64 translator can derive IPv4 from the IPv6 address
automatically — each host needs an explicit mapping entry (TAYGA `map` or
Jool EAMT).

## Design Details

### 1. IPv6 Capability Detection

New derivation: `src/gdoc2netcfg/derivations/ipv6_capability.py`

**Detection signals (OR logic — any match = incapable):**

- **MAC OUI**: Built-in set of Espressif/ITEAD OUI prefixes:
  `5C:CF:7F`, `C4:DD:57`, `70:03:9F`, `84:0D:8E`, `DC:4F:22`, `34:98:7A`,
  `E8:DB:84`, `7C:2C:67`, `24:EC:4A`, `A4:F0:0F`, `E0:8C:FE`, `C4:4F:33`

- **Hardware column regex**: Configurable patterns matched against `host.extra["Hardware"]`:
  `Athom.*`, `RF_R2`, `MINI$`, `ESP32-CAM`, `Sonoff.*`, `RFBridge.*`,
  `Stampher.*`, `NSPanel.*`, `GD-DC5`

Configuration in `gdoc2netcfg.toml`:
```toml
[ipv6_capability]
incapable_hardware_patterns = [
    "Athom.*",
    "RF_R2",
    "MINI$",
    "ESP32-CAM",
    "Sonoff.*",
    "RFBridge.*",
    "Stampher.*",
    "NSPanel.*",
    "GD-DC5",
]
# Additional OUI prefixes beyond built-in Espressif set
incapable_ouis = []
```

### 2. Host Model Change

Add `ipv6_capable: bool = True` to the `Host` class in `models/host.py`.

IPv6 addresses are still derived for ALL hosts. The flag controls downstream
behaviour, not derivation.

### 3. dnsmasq Generator Changes

Only the DHCP binding generation changes:

- `dhcp-host=` lines: **Skip IPv6 addresses** when `host.ipv6_capable is False`
- `host-record=` lines: **No change** — IPv6 AAAA records must be present so IPv6
  clients can resolve the address and reach TAYGA
- `ptr-record=` lines: **No change** — the IPv6 address exists (on ten64's TUN),
  reverse DNS should work
- CAA, SSHFP: **No change**

### 4. New TAYGA Generator

New generator: `src/gdoc2netcfg/generators/tayga.py`

Produces three output files:

**`tayga/tayga.conf`:**
```
tun-device nat64
ipv4-addr 100.64.1.1
data-dir /var/lib/tayga

# au-plug-1 (10.1.90.51 <-> 2404:e80:a137:190::51)
map 10.1.90.51  2404:e80:a137:190::51
# au-plug-2 (10.1.90.52 <-> 2404:e80:a137:190::52)
map 10.1.90.52  2404:e80:a137:190::52
```

**`tayga/nat64.netdev`:**
```ini
[NetDev]
Name=nat64
Kind=tun
```

**`tayga/nat64.network`:**
```ini
[Match]
Name=nat64

[Network]
Address=100.64.1.1/32

[Route]
Destination=2404:e80:a137:190::51/128

[Route]
Destination=2404:e80:a137:190::52/128
```

Only hosts with `ipv6_capable=False` that have both IPv4 and derived IPv6
addresses generate entries.

Configuration in `gdoc2netcfg.toml`:
```toml
[generators.tayga]
output_dir = "tayga"
tun_device = "nat64"
ipv4_addr = "100.64.1.1"
```

### 5. Prefilter Utility

New utility: `src/gdoc2netcfg/derivations/ipv6_filter.py`

A composable pipeline pass `strip_ipv6_for_incapable(hosts)` that removes IPv6
addresses from incapable hosts. Available for future generators that want a
simplified view without thinking about IPv6 capability. Not used by current
generators (dnsmasq needs the native approach; others don't use IPv6).

### 6. Pipeline Integration

In `cli/main.py` `_build_pipeline()`:

1. After `build_hosts()` — run `detect_ipv6_capability()` to set flags
2. No change to DNS name derivation or inventory building
3. Add `tayga` to the generator registry

### 7. Deployment

On ten64:
```bash
# Install TAYGA
sudo apt install tayga

# Generate configs
cd /opt/gdoc2netcfg
uv run gdoc2netcfg generate tayga

# Deploy
sudo cp tayga/tayga.conf /etc/tayga.conf
sudo cp tayga/nat64.netdev /etc/systemd/network/
sudo cp tayga/nat64.network /etc/systemd/network/

# Create persistent TUN device and start
sudo tayga --mktun
sudo networkctl reload
sudo systemctl enable --now tayga
```

## What Does NOT Change

- IPv6 derivation logic (`ipv6.py`) — all hosts still get IPv6 derived
- DNS name derivation (`dns_names.py`) — all 5 passes work identically
- nginx generator — already handles IPv6 correctly
- nagios, letsencrypt, topology generators — don't use IPv6
- External dnsmasq — same host-record changes as internal

## Testing Strategy

- Unit tests for `ipv6_capability.py` (OUI matching, regex matching)
- Update dnsmasq tests to verify DHCP excludes IPv6 for incapable hosts
- Update dnsmasq tests to verify host-record KEEPS IPv6 for incapable hosts
- New tests for TAYGA config generation
- Integration test: end-to-end with sample IoT CSV fixtures

## Future Considerations

- Per-device override column in spreadsheet ("IPv6 Capable: yes/no")
- Monitoring/validation constraint: check TAYGA is running on ten64
- Monarto site: TAYGA config generation for 10.2.90.x devices
