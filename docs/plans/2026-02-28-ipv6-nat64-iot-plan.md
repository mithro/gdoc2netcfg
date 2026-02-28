# IPv6 NAT64 for IoT Devices — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Detect IPv6-incapable IoT devices (by MAC OUI and Hardware column regex), skip their IPv6 in DHCP bindings, and generate TAYGA NAT64 config so IPv6 clients can still reach them via the site gateway.

**Architecture:** A new `ipv6_capable` flag on `Host` drives two changes: dnsmasq skips IPv6 in DHCP for incapable hosts (DNS records kept), and a new TAYGA generator produces NAT64 config mapping their IPv6 addresses to IPv4 via the 100.64.x.x source range.

**Tech Stack:** Python 3.11+, dataclasses, regex, existing gdoc2netcfg pipeline. TAYGA config is plain text, systemd-networkd is INI-like.

**Design doc:** `docs/plans/2026-02-28-ipv6-nat64-iot-design.md`

---

### Task 1: Add `ipv6_capable` field to Host model

**Files:**
- Modify: `src/gdoc2netcfg/models/host.py:334` (after `tasmota_data` field)
- Test: `tests/test_models/test_host.py`

**Step 1: Write the failing test**

In `tests/test_models/test_host.py`, add:

```python
def test_host_ipv6_capable_defaults_to_true():
    host = Host(machine_name="test", hostname="test")
    assert host.ipv6_capable is True


def test_host_ipv6_capable_can_be_set_false():
    host = Host(machine_name="test", hostname="test", ipv6_capable=False)
    assert host.ipv6_capable is False
```

**Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_models/test_host.py::test_host_ipv6_capable_defaults_to_true -v`
Expected: FAIL — `Host.__init__() got an unexpected keyword argument 'ipv6_capable'`

**Step 3: Write minimal implementation**

In `src/gdoc2netcfg/models/host.py`, add after line 334 (`tasmota_data: TasmotaData | None = None`):

```python
    ipv6_capable: bool = True
```

**Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_models/test_host.py::test_host_ipv6_capable_defaults_to_true tests/test_models/test_host.py::test_host_ipv6_capable_can_be_set_false -v`
Expected: PASS

**Step 5: Run full test suite to check for regressions**

Run: `uv run pytest -x`
Expected: All existing tests still pass (the field defaults to `True`)

**Step 6: Commit**

```
feat(models): add ipv6_capable flag to Host

Defaults to True. Will be set to False by IPv6 capability detection
for devices that don't support IPv6 (ESP-based IoT devices).
```

---

### Task 2: Create IPv6 capability detection module

**Files:**
- Create: `src/gdoc2netcfg/derivations/ipv6_capability.py`
- Create: `tests/test_derivations/test_ipv6_capability.py`

**Step 1: Write the failing tests**

Create `tests/test_derivations/test_ipv6_capability.py`:

```python
"""Tests for IPv6 capability detection."""

from gdoc2netcfg.derivations.ipv6_capability import (
    ESPRESSIF_OUIS,
    detect_ipv6_capability,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface


def _make_host(hostname, mac, ip="10.1.90.51", extra=None):
    ipv4 = IPv4Address(ip)
    iface = NetworkInterface(
        name=None,
        mac=MACAddress.parse(mac),
        ip_addresses=(ipv4,),
        dhcp_name=hostname,
    )
    return Host(
        machine_name=hostname,
        hostname=hostname,
        sheet_type="IoT",
        interfaces=[iface],
        default_ipv4=ipv4,
        extra=extra or {},
    )


class TestEspressifOuiDetection:
    """Hosts with Espressif MAC OUIs are IPv6-incapable."""

    def test_espressif_oui_detected(self):
        # 7C:2C:67 is an Espressif OUI (Athom plugs)
        host = _make_host("au-plug-1", "7C:2C:67:D9:BA:24")
        assert detect_ipv6_capability(host) is False

    def test_itead_oui_detected(self):
        # C4:4F:33 is ITEAD (Sonoff devices)
        host = _make_host("bridge-433-1", "C4:4F:33:E7:04:FA")
        assert detect_ipv6_capability(host) is False

    def test_non_espressif_mac_is_capable(self):
        # Regular NIC MAC — not in OUI set
        host = _make_host("desktop", "aa:bb:cc:dd:ee:ff")
        assert detect_ipv6_capability(host) is True

    def test_netgear_mac_is_capable(self):
        # Netgear switches support IPv6
        host = _make_host("switch", "38:94:ed:b7:cd:e0")
        assert detect_ipv6_capability(host) is True

    def test_oui_set_has_known_prefixes(self):
        assert "7c:2c:67" in ESPRESSIF_OUIS
        assert "c4:4f:33" in ESPRESSIF_OUIS
        assert "5c:cf:7f" in ESPRESSIF_OUIS


class TestHardwarePatternDetection:
    """Hosts matching hardware column regex patterns are IPv6-incapable."""

    def test_athom_plug_pattern(self):
        host = _make_host("au-plug-1", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "Athom Plug V3"})
        patterns = ["Athom.*"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False

    def test_rf_r2_pattern(self):
        host = _make_host("light1", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "RF_R2"})
        patterns = ["RF_R2"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False

    def test_mini_pattern(self):
        host = _make_host("switch1", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "MINI"})
        patterns = ["MINI$"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False

    def test_no_hardware_column_is_capable(self):
        host = _make_host("desktop", "aa:bb:cc:dd:ee:ff")
        patterns = ["Athom.*", "RF_R2"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is True

    def test_unmatched_hardware_is_capable(self):
        host = _make_host("server", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "Raspberry Pi 5"})
        patterns = ["Athom.*", "RF_R2"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is True

    def test_pattern_is_case_insensitive(self):
        host = _make_host("plug", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "athom plug v3"})
        patterns = ["Athom.*"]
        assert detect_ipv6_capability(host, hardware_patterns=patterns) is False


class TestCombinedDetection:
    """OUI and hardware patterns work together (OR logic)."""

    def test_oui_match_overrides_no_hardware(self):
        # Espressif OUI, no hardware column
        host = _make_host("esp-device", "7C:2C:67:D9:BA:24")
        assert detect_ipv6_capability(host) is False

    def test_hardware_match_overrides_unknown_oui(self):
        # Unknown OUI, but matching hardware pattern
        host = _make_host("plug", "aa:bb:cc:dd:ee:ff",
                          extra={"Hardware": "Athom Plug V3"})
        assert detect_ipv6_capability(host, hardware_patterns=["Athom.*"]) is False

    def test_extra_ouis_extend_detection(self):
        host = _make_host("custom", "11:22:33:44:55:66")
        assert detect_ipv6_capability(host) is True
        assert detect_ipv6_capability(host, extra_ouis={"11:22:33"}) is False
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_derivations/test_ipv6_capability.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gdoc2netcfg.derivations.ipv6_capability'`

**Step 3: Write minimal implementation**

Create `src/gdoc2netcfg/derivations/ipv6_capability.py`:

```python
"""IPv6 capability detection for network hosts.

Determines whether a host supports IPv6 based on MAC OUI prefix matching
and hardware column regex patterns. Hosts using Espressif/ITEAD chipsets
(ESP8266, ESP32-C3 running Tasmota) typically lack IPv6 support.

Used by the pipeline to:
- Skip IPv6 in DHCP bindings for incapable devices
- Generate TAYGA NAT64 mappings so IPv6 clients can still reach them
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host

# IEEE OUI prefixes for Espressif Systems (ESP8266, ESP32, ESP32-C3, etc.)
# and ITEAD (Sonoff devices using Espressif chips).
# Source: https://maclookup.app/vendors/espressif-inc
ESPRESSIF_OUIS: set[str] = {
    "5c:cf:7f",   # Espressif (ESP8266)
    "c4:dd:57",   # Espressif (ESP32-C3)
    "70:03:9f",   # Espressif
    "84:0d:8e",   # Espressif
    "dc:4f:22",   # Espressif / ITEAD (Sonoff)
    "34:98:7a",   # Espressif (Athom IR remotes)
    "e8:db:84",   # Espressif
    "7c:2c:67",   # Espressif (Athom plugs — ESP32-C3)
    "24:ec:4a",   # Espressif (Athom plugs)
    "a4:f0:0f",   # Espressif (ESP32-CAM)
    "e0:8c:fe",   # Espressif (ESP32-CAM)
    "c4:4f:33",   # ITEAD (Sonoff RFBridge, Sonoff SC)
    "88:12:ac",   # Espressif (NSPanel)
}


def _mac_oui(mac_address: str) -> str:
    """Extract the OUI prefix (first 3 octets) from a MAC address."""
    return mac_address[:8].lower()


def detect_ipv6_capability(
    host: "Host",
    *,
    hardware_patterns: list[str] | None = None,
    extra_ouis: set[str] | None = None,
) -> bool:
    """Determine whether a host supports IPv6.

    Returns False (incapable) if ANY of:
    - Any interface MAC OUI matches the Espressif/ITEAD set or extra_ouis
    - The 'Hardware' extra field matches any of the hardware_patterns regexes

    Returns True (capable) otherwise.

    Args:
        host: The host to check.
        hardware_patterns: Regex patterns to match against host.extra["Hardware"].
            If None, no hardware pattern matching is performed.
        extra_ouis: Additional OUI prefixes to treat as IPv6-incapable,
            beyond the built-in Espressif set.
    """
    # Check MAC OUI
    all_incapable_ouis = ESPRESSIF_OUIS
    if extra_ouis:
        all_incapable_ouis = ESPRESSIF_OUIS | {oui.lower() for oui in extra_ouis}

    host_ouis = {_mac_oui(str(mac)) for mac in host.all_macs}
    if host_ouis & all_incapable_ouis:
        return False

    # Check hardware column patterns
    if hardware_patterns:
        hardware_value = host.extra.get("Hardware", "")
        if hardware_value:
            for pattern in hardware_patterns:
                if re.search(pattern, hardware_value, re.IGNORECASE):
                    return False

    return True
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_derivations/test_ipv6_capability.py -v`
Expected: All PASS

**Step 5: Lint**

Run: `uv run ruff check src/gdoc2netcfg/derivations/ipv6_capability.py tests/test_derivations/test_ipv6_capability.py`

**Step 6: Commit**

```
feat(derivations): add IPv6 capability detection

Detects IPv6-incapable devices by MAC OUI (Espressif/ITEAD chipsets)
and configurable hardware column regex patterns. Returns False for
devices like Tasmota smart plugs that don't support IPv6.
```

---

### Task 3: Add IPv6 capability config section

**Files:**
- Modify: `src/gdoc2netcfg/config.py` (add `IPv6CapabilityConfig` dataclass and parser)
- Test: `tests/test_sources/test_config.py`

**Step 1: Write the failing test**

In `tests/test_sources/test_config.py`, add:

```python
def test_ipv6_capability_config_defaults():
    """IPv6 capability config has sensible defaults when section is missing."""
    from gdoc2netcfg.config import IPv6CapabilityConfig
    config = IPv6CapabilityConfig()
    assert config.incapable_hardware_patterns == []
    assert config.incapable_ouis == []


def test_ipv6_capability_config_from_toml(tmp_path):
    """IPv6 capability config is parsed from [ipv6_capability] section."""
    from gdoc2netcfg.config import load_config
    toml_file = tmp_path / "gdoc2netcfg.toml"
    toml_file.write_text('''
[site]
name = "test"
domain = "test.example.com"
site_octet = 1

[ipv6_capability]
incapable_hardware_patterns = ["Athom.*", "RF_R2"]
incapable_ouis = ["aa:bb:cc"]
''')
    config = load_config(toml_file)
    assert config.ipv6_capability.incapable_hardware_patterns == ["Athom.*", "RF_R2"]
    assert config.ipv6_capability.incapable_ouis == ["aa:bb:cc"]
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_sources/test_config.py::test_ipv6_capability_config_defaults -v`
Expected: FAIL — `ImportError: cannot import name 'IPv6CapabilityConfig'`

**Step 3: Write minimal implementation**

In `src/gdoc2netcfg/config.py`, add the dataclass (after `HomeAssistantConfig`):

```python
@dataclass
class IPv6CapabilityConfig:
    """Configuration for IPv6 capability detection.

    Controls which devices are detected as IPv6-incapable based on
    hardware column regex patterns and MAC OUI prefixes.
    """

    incapable_hardware_patterns: list[str] = field(default_factory=list)
    incapable_ouis: list[str] = field(default_factory=list)
```

Add field to `PipelineConfig`:

```python
    ipv6_capability: IPv6CapabilityConfig = field(default_factory=IPv6CapabilityConfig)
```

Add builder function:

```python
def _build_ipv6_capability(data: dict) -> IPv6CapabilityConfig:
    """Build IPv6 capability config from parsed TOML data."""
    section = data.get("ipv6_capability", {})
    if not section:
        return IPv6CapabilityConfig()
    return IPv6CapabilityConfig(
        incapable_hardware_patterns=list(section.get("incapable_hardware_patterns", [])),
        incapable_ouis=list(section.get("incapable_ouis", [])),
    )
```

Wire it into `load_config()`:

```python
    return PipelineConfig(
        site=_build_site(data),
        sheets=_build_sheets(data),
        cache=CacheConfig(
            directory=Path(data.get("cache", {}).get("directory", ".cache")),
        ),
        generators=_build_generators(data),
        tasmota=_build_tasmota(data),
        homeassistant=_build_homeassistant(data),
        ipv6_capability=_build_ipv6_capability(data),
    )
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_sources/test_config.py -v`
Expected: All PASS

**Step 5: Commit**

```
feat(config): add [ipv6_capability] config section

Supports incapable_hardware_patterns (regex list) and incapable_ouis
(MAC OUI prefix list) for configuring IPv6 capability detection.
```

---

### Task 4: Wire IPv6 capability detection into the pipeline

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (in `_build_pipeline()`)
- Test: `tests/test_derivations/test_host_builder.py`

**Step 1: Write the failing test**

In `tests/test_derivations/test_host_builder.py`, add:

```python
def test_build_hosts_espressif_device_not_ipv6_capable():
    """Hosts with Espressif MAC OUIs should have ipv6_capable=False."""
    from gdoc2netcfg.derivations.ipv6_capability import detect_ipv6_capability

    records = [_make_record(
        machine="au-plug-1",
        mac="7C:2C:67:D9:BA:24",  # Espressif OUI
        ip="10.1.90.51",
        sheet_name="IoT",
    )]
    hosts = build_hosts(records, SITE)
    assert len(hosts) == 1
    host = hosts[0]

    # Before detection, defaults to True
    assert host.ipv6_capable is True

    # After detection, Espressif OUI → False
    host.ipv6_capable = detect_ipv6_capability(host)
    assert host.ipv6_capable is False


def test_build_hosts_regular_device_ipv6_capable():
    """Hosts with non-Espressif MACs should remain ipv6_capable=True."""
    from gdoc2netcfg.derivations.ipv6_capability import detect_ipv6_capability

    records = [_make_record(
        machine="desktop",
        mac="aa:bb:cc:dd:ee:ff",
        ip="10.1.10.100",
    )]
    hosts = build_hosts(records, SITE)
    host = hosts[0]
    host.ipv6_capable = detect_ipv6_capability(host)
    assert host.ipv6_capable is True
```

Note: These tests verify the detection function works with hosts built by `build_hosts()`. The actual pipeline integration (calling detection in `_build_pipeline()`) is wired in `cli/main.py` — we verify it works end-to-end by running `uv run gdoc2netcfg info` after the change.

**Step 2: Run tests to verify they pass**

Run: `uv run pytest tests/test_derivations/test_host_builder.py -v`
Expected: All PASS (these tests use `detect_ipv6_capability` directly)

**Step 3: Wire detection into `_build_pipeline()`**

In `src/gdoc2netcfg/cli/main.py`, in `_build_pipeline()`, after the `build_hosts()` call (line 144) and before `build_inventory()`, add:

```python
    # Detect IPv6 capability from MAC OUI and hardware patterns
    from gdoc2netcfg.derivations.ipv6_capability import detect_ipv6_capability

    ipv6_cap = config.ipv6_capability
    extra_ouis = set(ipv6_cap.incapable_ouis) if ipv6_cap.incapable_ouis else None
    hardware_patterns = ipv6_cap.incapable_hardware_patterns or None
    for host in hosts:
        host.ipv6_capable = detect_ipv6_capability(
            host,
            hardware_patterns=hardware_patterns,
            extra_ouis=extra_ouis,
        )
```

**Step 4: Run full test suite**

Run: `uv run pytest -x`
Expected: All PASS

**Step 5: Commit**

```
feat(pipeline): wire IPv6 capability detection into build pipeline

Runs detect_ipv6_capability() on each host after build_hosts(),
using hardware patterns and extra OUIs from config.
```

---

### Task 5: Modify dnsmasq DHCP to skip IPv6 for incapable hosts

**Files:**
- Modify: `src/gdoc2netcfg/generators/dnsmasq.py:49-69` (`_host_dhcp_config`)
- Test: `tests/test_generators/test_dnsmasq.py`

**Step 1: Write the failing test**

In `tests/test_generators/test_dnsmasq.py`, add:

```python
class TestDhcpIpv6Capability:
    """DHCP bindings skip IPv6 for IPv6-incapable hosts."""

    def test_dhcp_excludes_ipv6_when_incapable(self):
        """IPv6-incapable hosts should have DHCP without IPv6 addresses."""
        host = _host_with_iface("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.10.51",
                                dhcp_name="au-plug-1")
        host.ipv6_capable = False
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.51": "au-plug-1"},
            ip_to_macs={"10.1.10.51": [(MACAddress.parse("7c:2c:67:d9:ba:24"), "au-plug-1")]},
        )
        result = generate_dnsmasq_internal(inv)
        conf = result["au-plug-1.conf"]
        # DHCP should NOT have [ipv6] brackets
        assert "dhcp-host=7c:2c:67:d9:ba:24,10.1.10.51,au-plug-1" in conf
        assert "[2404:" not in conf.split("host-record")[0]  # Before host-record section

    def test_dhcp_includes_ipv6_when_capable(self):
        """IPv6-capable hosts should have DHCP with IPv6 addresses as normal."""
        host = _host_with_iface("desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.100",
                                dhcp_name="desktop")
        # ipv6_capable defaults to True
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.100": "desktop"},
            ip_to_macs={"10.1.10.100": [(MACAddress.parse("aa:bb:cc:dd:ee:ff"), "desktop")]},
        )
        result = generate_dnsmasq_internal(inv)
        conf = result["desktop.conf"]
        assert "[2404:e80:a137:110::100]" in conf

    def test_host_record_keeps_ipv6_when_incapable(self):
        """host-record entries must keep AAAA records even for incapable hosts.

        IPv6 clients need the AAAA record to resolve the address that
        TAYGA will intercept for NAT64 translation.
        """
        host = _host_with_iface("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.10.51",
                                dhcp_name="au-plug-1")
        host.ipv6_capable = False
        inv = _make_inventory(
            hosts=[host],
            ip_to_hostname={"10.1.10.51": "au-plug-1"},
            ip_to_macs={"10.1.10.51": [(MACAddress.parse("7c:2c:67:d9:ba:24"), "au-plug-1")]},
        )
        result = generate_dnsmasq_internal(inv)
        conf = result["au-plug-1.conf"]
        # host-record MUST still contain IPv6 (for TAYGA NAT64)
        assert "host-record=au-plug-1.welland.mithis.com,10.1.10.51,2404:e80:a137:110::51" in conf
```

**Step 2: Run tests to verify the first one fails**

Run: `uv run pytest tests/test_generators/test_dnsmasq.py::TestDhcpIpv6Capability::test_dhcp_excludes_ipv6_when_incapable -v`
Expected: FAIL — DHCP line still contains `[2404:...]`

**Step 3: Modify `_host_dhcp_config`**

In `src/gdoc2netcfg/generators/dnsmasq.py`, modify `_host_dhcp_config()` to check `host.ipv6_capable`:

```python
def _host_dhcp_config(host: Host, inventory: NetworkInventory) -> list[str]:
    """Generate dhcp-host entries for a single host."""
    if not host.interfaces:
        return []

    output: list[str] = []
    output.append(f"# {host.hostname} — DHCP")
    for vi in sorted(host.virtual_interfaces, key=lambda v: ip_sort_key(str(v.ipv4))):
        ip = str(vi.ipv4)
        dhcp_name = common_suffix(*set(vi.dhcp_names)).strip("-")

        # Skip IPv6 in DHCP for hosts that don't support it —
        # their IPv6 addresses are handled by TAYGA NAT64 on the gateway
        ipv6_strs = _ipv6_for_ip(ip, inventory) if host.ipv6_capable else []
        mac_str = ",".join(str(mac) for mac in vi.macs)

        if ipv6_strs:
            ipv6_brackets = ",".join(f"[{addr}]" for addr in ipv6_strs)
            output.append(f"dhcp-host={mac_str},{ip},{ipv6_brackets},{dhcp_name}")
        else:
            output.append(f"dhcp-host={mac_str},{ip},{dhcp_name}")

    return output
```

The key change is on the `ipv6_strs` line: `_ipv6_for_ip(ip, inventory) if host.ipv6_capable else []`.

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_generators/test_dnsmasq.py::TestDhcpIpv6Capability -v`
Expected: All 3 PASS

**Step 5: Run full test suite**

Run: `uv run pytest -x`
Expected: All PASS

**Step 6: Commit**

```
feat(dnsmasq): skip IPv6 in DHCP for incapable hosts

DHCP bindings no longer include IPv6 addresses for hosts with
ipv6_capable=False. Host-record DNS entries still include AAAA
records so IPv6 clients can reach these devices via TAYGA NAT64.
```

---

### Task 6: Create TAYGA generator

**Files:**
- Create: `src/gdoc2netcfg/generators/tayga.py`
- Create: `tests/test_generators/test_tayga.py`

**Step 1: Write the failing tests**

Create `tests/test_generators/test_tayga.py`:

```python
"""Tests for the TAYGA NAT64 configuration generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.tayga import generate_tayga
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={90: "iot"},
)


def _make_host(hostname, mac, ip, ipv6_capable=True, sheet_type="IoT"):
    ipv4 = IPv4Address(ip)
    parts = ip.split(".")
    aa = parts[1]
    bb = parts[2].zfill(2)
    ccc = parts[3]
    ipv6 = IPv6Address(f"2404:e80:a137:{aa}{bb}::{ccc}", "2404:e80:a137:")

    iface = NetworkInterface(
        name=None,
        mac=MACAddress.parse(mac),
        ip_addresses=(ipv4, ipv6),
        dhcp_name=hostname,
    )
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        sheet_type=sheet_type,
        interfaces=[iface],
        default_ipv4=ipv4,
        subdomain="iot",
        ipv6_capable=ipv6_capable,
    )
    derive_all_dns_names(host, SITE)
    return host


def _make_inventory(*hosts):
    return NetworkInventory(
        site=SITE,
        hosts=list(hosts),
        ip_to_hostname={str(h.default_ipv4): h.hostname for h in hosts},
        ip_to_macs={},
    )


class TestTaygaGenerator:
    def test_returns_dict(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        assert isinstance(result, dict)

    def test_output_file_keys(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        assert "tayga.conf" in result
        assert "nat64.netdev" in result
        assert "nat64.network" in result

    def test_tayga_conf_has_map_entry(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "map 10.1.90.51\t2404:e80:a137:190::51" in conf

    def test_tayga_conf_has_header(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "tun-device nat64" in conf
        assert "ipv4-addr 100.64.1.1" in conf

    def test_tayga_conf_skips_capable_hosts(self):
        capable = _make_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.90.100",
                             ipv6_capable=True)
        incapable = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                               ipv6_capable=False)
        inv = _make_inventory(capable, incapable)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "10.1.90.51" in conf
        assert "10.1.90.100" not in conf

    def test_netdev_file(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        netdev = result["nat64.netdev"]
        assert "[NetDev]" in netdev
        assert "Name=nat64" in netdev
        assert "Kind=tun" in netdev

    def test_network_file_has_routes(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        network = result["nat64.network"]
        assert "Address=100.64.1.1/32" in network
        assert "Destination=2404:e80:a137:190::51/128" in network

    def test_empty_when_no_incapable_hosts(self):
        host = _make_host("desktop", "aa:bb:cc:dd:ee:ff", "10.1.90.100",
                          ipv6_capable=True)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "map " not in conf

    def test_multiple_incapable_hosts(self):
        hosts = [
            _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                       ipv6_capable=False),
            _make_host("au-plug-2", "7c:2c:67:d8:b9:60", "10.1.90.52",
                       ipv6_capable=False),
        ]
        inv = _make_inventory(*hosts)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "map 10.1.90.51" in conf
        assert "map 10.1.90.52" in conf
        network = result["nat64.network"]
        assert "Destination=2404:e80:a137:190::51/128" in network
        assert "Destination=2404:e80:a137:190::52/128" in network

    def test_configurable_tun_device_name(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv, tun_device="nat64-iot")
        assert "tun-device nat64-iot" in result["tayga.conf"]
        assert "Name=nat64-iot" in result["nat64-iot.netdev"]
        assert "Name=nat64-iot" in result["nat64-iot.network"]

    def test_configurable_ipv4_addr(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv, ipv4_addr="100.64.2.1")
        assert "ipv4-addr 100.64.2.1" in result["tayga.conf"]

    def test_comment_includes_hostname(self):
        host = _make_host("au-plug-1", "7c:2c:67:d9:ba:24", "10.1.90.51",
                          ipv6_capable=False)
        inv = _make_inventory(host)
        result = generate_tayga(inv)
        conf = result["tayga.conf"]
        assert "# au-plug-1" in conf
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_generators/test_tayga.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'gdoc2netcfg.generators.tayga'`

**Step 3: Write the implementation**

Create `src/gdoc2netcfg/generators/tayga.py`:

```python
"""TAYGA NAT64 configuration generator.

Produces TAYGA config and systemd-networkd files for IPv6-to-IPv4
translation of IPv6-incapable devices. The gateway (ten64) runs TAYGA
as a userspace NAT64 daemon, translating IPv6 traffic to IPv4 so that
IPv6 clients can reach IPv4-only IoT devices.

Output files:
- tayga.conf: TAYGA daemon configuration with per-host map entries
- {tun}.netdev: systemd-networkd TUN device definition
- {tun}.network: systemd-networkd network config with per-host IPv6 routes
"""

from __future__ import annotations

from gdoc2netcfg.models.host import NetworkInventory
from gdoc2netcfg.utils.ip import ip_sort_key


def generate_tayga(
    inventory: NetworkInventory,
    *,
    tun_device: str = "nat64",
    ipv4_addr: str = "100.64.1.1",
) -> dict[str, str]:
    """Generate TAYGA NAT64 configuration files.

    Produces map entries only for hosts with ipv6_capable=False that
    have both IPv4 and IPv6 addresses.

    Args:
        inventory: The fully enriched network inventory.
        tun_device: Name of the TUN device for TAYGA (default: "nat64").
        ipv4_addr: IPv4 address for TAYGA's TUN endpoint, used as the
            source address for translated packets. Should be in the
            RFC 6598 (100.64.0.0/10) range so devices can distinguish
            NAT64-proxied connections.

    Returns:
        Dict mapping filename to file content:
        - "tayga.conf": TAYGA daemon configuration
        - "{tun_device}.netdev": systemd-networkd TUN device
        - "{tun_device}.network": systemd-networkd network config
    """
    # Collect NAT64 mappings for incapable hosts
    mappings: list[tuple[str, str, str, str]] = []  # (hostname, ipv4, ipv6, sort_key)
    for host in inventory.hosts_sorted():
        if host.ipv6_capable:
            continue
        if host.default_ipv4 is None:
            continue
        # Get the first IPv6 address from the default interface
        for iface in host.interfaces:
            if iface.ipv4 == host.default_ipv4 and iface.ipv6_addresses:
                ipv4_str = str(iface.ipv4)
                ipv6_str = str(iface.ipv6_addresses[0])
                mappings.append((host.hostname, ipv4_str, ipv6_str, ipv4_str))
                break

    # Sort by IPv4 address
    mappings.sort(key=lambda m: ip_sort_key(m[3]))

    # Generate tayga.conf
    tayga_lines = [
        f"tun-device {tun_device}",
        f"ipv4-addr {ipv4_addr}",
        "data-dir /var/lib/tayga",
        "",
    ]
    for hostname, ipv4, ipv6, _ in mappings:
        tayga_lines.append(f"# {hostname}")
        tayga_lines.append(f"map {ipv4}\t{ipv6}")
    tayga_conf = "\n".join(tayga_lines) + "\n"

    # Generate systemd-networkd .netdev
    netdev = (
        f"[NetDev]\n"
        f"Name={tun_device}\n"
        f"Kind=tun\n"
    )

    # Generate systemd-networkd .network with per-host IPv6 routes
    network_lines = [
        f"[Match]",
        f"Name={tun_device}",
        f"",
        f"[Network]",
        f"Address={ipv4_addr}/32",
    ]
    for _, _, ipv6, _ in mappings:
        network_lines.append(f"")
        network_lines.append(f"[Route]")
        network_lines.append(f"Destination={ipv6}/128")
    network = "\n".join(network_lines) + "\n"

    return {
        "tayga.conf": tayga_conf,
        f"{tun_device}.netdev": netdev,
        f"{tun_device}.network": network,
    }
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_generators/test_tayga.py -v`
Expected: All PASS

**Step 5: Lint**

Run: `uv run ruff check src/gdoc2netcfg/generators/tayga.py tests/test_generators/test_tayga.py`

**Step 6: Commit**

```
feat(generators): add TAYGA NAT64 config generator

Generates tayga.conf with per-host map entries, systemd-networkd
.netdev for the TUN device, and .network with IPv6 routes. Only
creates mappings for hosts with ipv6_capable=False.
```

---

### Task 7: Wire TAYGA generator into the registry

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (generator registry + parameter handling)

**Step 1: Add TAYGA to the generator registry**

In `src/gdoc2netcfg/cli/main.py`, in `_get_generator()` function, add to the `generators` dict (after the topology entry):

```python
    "tayga": ("gdoc2netcfg.generators.tayga", "generate_tayga"),
```

**Step 2: Add parameter handling in `cmd_generate()`**

In the parameter handling section of `cmd_generate()` (around line 341), add:

```python
    elif name == "tayga" and gen_config:
        if gen_config.params.get("tun_device"):
            kwargs["tun_device"] = gen_config.params["tun_device"]
        if gen_config.params.get("ipv4_addr"):
            kwargs["ipv4_addr"] = gen_config.params["ipv4_addr"]
```

**Step 3: Run full test suite**

Run: `uv run pytest -x`
Expected: All PASS

**Step 4: Commit**

```
feat(cli): register TAYGA generator in pipeline

Adds 'tayga' to the generator registry with tun_device and
ipv4_addr parameters from [generators.tayga] config section.
```

---

### Task 8: Update example config and IoT test fixture

**Files:**
- Modify: `gdoc2netcfg.toml.example`
- Modify: `tests/fixtures/sample_iot.csv`

**Step 1: Update example config**

In `gdoc2netcfg.toml.example`, add before the `[generators]` section:

```toml
# ── IPv6 capability detection ────────────────────────────────────
[ipv6_capability]
# Devices matching any of these Hardware column patterns are
# considered IPv6-incapable. Their IPv6 addresses will be served
# by TAYGA NAT64 on the gateway instead of the device itself.
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
# Additional MAC OUI prefixes beyond built-in Espressif/ITEAD set
# incapable_ouis = []
```

And add the tayga generator config:

```toml
[generators.tayga]
output_dir = "tayga"
tun_device = "nat64"
ipv4_addr = "100.64.1.1"
```

Note: Don't add `tayga` to the `enabled` list by default — sites opt in.

**Step 2: Update IoT test fixture**

Update `tests/fixtures/sample_iot.csv` to include an Espressif MAC so the
fixture is more realistic for IPv6 capability testing:

```csv
Machine,MAC Address,IP,Interface,Hardware
thermostat,aa:00:11:22:33:44,10.1.90.10,,ESP32
camera-front,bb:00:11:22:33:44,10.1.90.20,,Reolink
au-plug-1,7c:2c:67:d9:ba:24,10.1.90.51,,Athom Plug V3
```

**Step 3: Run full test suite to ensure no regressions**

Run: `uv run pytest -x`
Expected: All PASS

**Step 4: Commit**

```
feat(config): add IPv6 capability and TAYGA to example config

Adds [ipv6_capability] section with default hardware patterns for
Tasmota/ESP devices, and [generators.tayga] for NAT64 config.
Updates IoT test fixture with Espressif MAC and Hardware column.
```

---

### Task 9: Final verification

**Step 1: Run full lint + test suite**

```bash
uv run ruff check src/ tests/
uv run pytest -v
```

**Step 2: Verify all new files are tracked**

```bash
git status
```

Expected new files:
- `src/gdoc2netcfg/derivations/ipv6_capability.py`
- `src/gdoc2netcfg/generators/tayga.py`
- `tests/test_derivations/test_ipv6_capability.py`
- `tests/test_generators/test_tayga.py`

Expected modified files:
- `src/gdoc2netcfg/models/host.py` (ipv6_capable field)
- `src/gdoc2netcfg/config.py` (IPv6CapabilityConfig)
- `src/gdoc2netcfg/cli/main.py` (pipeline + registry)
- `src/gdoc2netcfg/generators/dnsmasq.py` (DHCP IPv6 skip)
- `gdoc2netcfg.toml.example` (config sections)
- `tests/fixtures/sample_iot.csv` (Espressif fixture)
