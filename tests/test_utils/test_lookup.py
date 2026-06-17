"""Tests for device lookup utilities."""

from __future__ import annotations

import pytest

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.utils.lookup import (
    _match_by_mac,
    available_credential_fields,
    detect_query_type,
    get_credential_fields,
    lookup_host,
    suggest_matches,
)

# --- Helpers ----------------------------------------------------------------

def _make_host(
    machine_name: str,
    hostname: str,
    ip: str = "10.1.10.1",
    mac: str = "aa:bb:cc:dd:ee:01",
    extra: dict[str, str] | None = None,
) -> Host:
    """Build a minimal Host for testing."""
    iface = NetworkInterface(
        name=None,
        mac=MACAddress(mac),
        ip_addresses=(IPv4Address(ip),),
    )
    return Host(
        machine_name=machine_name,
        hostname=hostname,
        interfaces=[iface],
        extra=extra or {},
    )


def _make_multi_iface_host(
    machine_name: str,
    hostname: str,
    interfaces: list[tuple[str | None, str, str]],
    extra: dict[str, str] | None = None,
) -> Host:
    """Build a Host with multiple interfaces.

    Each interface is (name, ip, mac).
    """
    ifaces = [
        NetworkInterface(
            name=name,
            mac=MACAddress(mac),
            ip_addresses=(IPv4Address(ip),),
        )
        for name, ip, mac in interfaces
    ]
    return Host(
        machine_name=machine_name,
        hostname=hostname,
        interfaces=ifaces,
        extra=extra or {},
    )


# --- TestDetectQueryType ----------------------------------------------------

class TestDetectQueryType:
    def test_mac_colon_format(self):
        assert detect_query_type("aa:bb:cc:dd:ee:ff") == "mac"

    def test_mac_colon_uppercase(self):
        assert detect_query_type("AA:BB:CC:DD:EE:FF") == "mac"

    def test_mac_dash_format(self):
        assert detect_query_type("aa-bb-cc-dd-ee-ff") == "mac"

    def test_mac_dot_format(self):
        assert detect_query_type("aabb.ccdd.eeff") == "mac"

    def test_ipv4(self):
        assert detect_query_type("10.1.10.1") == "ip"

    def test_ipv4_high_octets(self):
        assert detect_query_type("192.168.1.255") == "ip"

    def test_hostname_simple(self):
        assert detect_query_type("switch1") == "hostname"

    def test_hostname_fqdn(self):
        assert detect_query_type("switch1.net.welland.mithis.com") == "hostname"

    def test_hostname_with_dots_but_not_ip(self):
        assert detect_query_type("bmc.big-storage") == "hostname"

    def test_whitespace_stripped(self):
        assert detect_query_type("  10.1.10.1  ") == "ip"

    def test_invalid_ip_octets_classified_as_hostname(self):
        """IPs with out-of-range octets are treated as hostnames."""
        assert detect_query_type("999.999.999.999") == "hostname"
        assert detect_query_type("256.0.0.1") == "hostname"


# --- TestMatchByHostname ----------------------------------------------------

class TestMatchByHostname:
    @pytest.fixture
    def hosts(self):
        return [
            # Network devices: hostname == machine_name (short)
            _make_host("switch1", "switch1",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("switch10", "switch10",
                        ip="10.1.30.10", mac="aa:bb:cc:dd:ee:04"),
            _make_host("big-storage", "big-storage",
                        ip="10.1.10.3", mac="aa:bb:cc:dd:ee:03"),
            # BMC: hostname "bmc.big-storage", machine_name shared with parent
            _make_host("big-storage", "bmc.big-storage",
                        ip="10.1.10.4", mac="aa:bb:cc:dd:ee:05"),
            # IoT: hostname carries the ".iot" suffix, machine_name is short
            _make_host("au-plug-1", "au-plug-1.iot",
                        ip="10.1.90.71", mac="aa:bb:cc:dd:ee:06"),
        ]

    def test_exact_hostname_match(self, hosts):
        results = lookup_host("switch1", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "switch1"
        assert results[0].match_type == "exact"

    def test_case_insensitive(self, hosts):
        results = lookup_host("SWITCH1", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "switch1"

    def test_bmc_collision_resolved(self, hosts):
        """'big-storage' must resolve ONLY the primary, never bmc.big-storage."""
        results = lookup_host("big-storage", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "big-storage"
        assert results[0].match_type == "exact"

    def test_bmc_reached_by_full_hostname(self, hosts):
        results = lookup_host("bmc.big-storage", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "bmc.big-storage"

    def test_machine_name_not_matched(self, hosts):
        """machine_name no longer matches: 'au-plug-1' != hostname 'au-plug-1.iot'."""
        assert lookup_host("au-plug-1", hosts) == []

    def test_iot_full_hostname_matches(self, hosts):
        results = lookup_host("au-plug-1.iot", hosts)
        assert len(results) == 1
        assert results[0].host.hostname == "au-plug-1.iot"

    def test_substring_no_longer_matches(self, hosts):
        """'storage' was a substring of 'big-storage'; now no match."""
        assert lookup_host("storage", hosts) == []

    def test_prefix_no_longer_matches(self, hosts):
        """'switch1' must NOT prefix-match 'switch10'."""
        matched = {r.host.hostname for r in lookup_host("switch1", hosts)}
        assert matched == {"switch1"}
        assert "switch10" not in matched

    def test_no_match(self, hosts):
        assert lookup_host("nonexistent", hosts) == []


# --- TestMatchByIP ----------------------------------------------------------

class TestMatchByIP:
    @pytest.fixture
    def hosts(self):
        return [
            _make_host("switch1", "switch1",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("server1", "server1",
                        ip="10.1.10.5", mac="aa:bb:cc:dd:ee:02"),
            # Same octets 1/3/4 as switch1 but a different second octet:
            _make_host("switch1-m", "switch1-m",
                        ip="10.2.30.1", mac="aa:bb:cc:dd:ee:03"),
        ]

    def test_exact_ip_match(self, hosts):
        results = lookup_host("10.1.30.1", hosts)
        assert results[0].host.hostname == "switch1"
        assert results[0].match_type == "exact"

    def test_exact_shadows_wildcard(self, hosts):
        """An exact hit suppresses the wildcard tier entirely."""
        results = lookup_host("10.1.30.1", hosts)
        assert len(results) == 1
        assert all(r.match_type == "exact" for r in results)
        assert results[0].host.hostname == "switch1"

    def test_wildcard_only_when_no_exact(self, hosts):
        """No host has 10.3.30.1, so the wildcard tier is returned."""
        results = lookup_host("10.3.30.1", hosts)
        assert len(results) == 2
        hostnames = {r.host.hostname for r in results}
        assert hostnames == {"switch1", "switch1-m"}
        assert all(r.match_type == "wildcard" for r in results)

    def test_no_match(self, hosts):
        assert lookup_host("10.1.99.99", hosts) == []


# --- TestMatchByMAC ---------------------------------------------------------

class TestMatchByMAC:
    @pytest.fixture
    def hosts(self):
        return [
            _make_host("switch1", "switch1.net.welland.mithis.com",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("server1", "server1.int.welland.mithis.com",
                        ip="10.1.10.5", mac="11:22:33:44:55:66"),
        ]

    def test_exact_mac_match(self, hosts):
        results = lookup_host("aa:bb:cc:dd:ee:01", hosts)
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"
        assert results[0].match_type == "exact"

    def test_dash_format_normalized(self, hosts):
        results = lookup_host("aa-bb-cc-dd-ee-01", hosts)
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"

    def test_dot_format_normalized(self, hosts):
        results = lookup_host("aabb.ccdd.ee01", hosts)
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"

    def test_uppercase_mac(self, hosts):
        results = lookup_host("AA:BB:CC:DD:EE:01", hosts)
        assert len(results) == 1
        assert results[0].host.machine_name == "switch1"

    def test_no_match(self, hosts):
        results = lookup_host("ff:ff:ff:ff:ff:ff", hosts)
        assert results == []

    def test_invalid_mac_raises(self, hosts):
        """An invalid MAC passed directly to _match_by_mac raises ValueError."""
        with pytest.raises(ValueError):
            _match_by_mac("not-a-mac", hosts)

    def test_invalid_mac_detected_as_hostname(self, hosts):
        """A MAC-like string with non-hex chars is treated as hostname."""
        # 'zz' is not valid hex, so detect_query_type classifies as hostname
        results = lookup_host("zz:zz:zz:zz:zz:zz", hosts)
        assert results == []


# --- TestSuggestMatches -----------------------------------------------------

class TestSuggestMatches:
    def test_close_hostname(self):
        """Fuzzy matching against the hostname (exact lookup identifier)."""
        hosts = [
            _make_host("switch1", "switch1",
                        ip="10.1.30.1", mac="aa:bb:cc:dd:ee:01"),
            _make_host("switch2", "switch2",
                        ip="10.1.30.2", mac="aa:bb:cc:dd:ee:02"),
        ]
        suggestions = suggest_matches("swtich1", hosts)
        assert len(suggestions) > 0
        assert "switch1" in suggestions

    def test_max_limit(self):
        hosts = [
            _make_host(f"host{i}", f"host{i}.test.com",
                        ip=f"10.1.10.{i}", mac=f"aa:bb:cc:dd:ee:{i:02x}")
            for i in range(1, 20)
        ]
        suggestions = suggest_matches("host", hosts, max_suggestions=3)
        assert len(suggestions) <= 3

    def test_no_close_matches(self):
        hosts = [
            _make_host("alpha", "alpha.test.com",
                        ip="10.1.10.1", mac="aa:bb:cc:dd:ee:01"),
        ]
        suggestions = suggest_matches("zzzzzzzzzzz", hosts)
        assert suggestions == []

    def test_suggests_full_hostname_not_machine_name(self):
        """A short IoT name should suggest the resolvable '.iot' hostname,
        not the bare machine_name (which no longer resolves)."""
        hosts = [
            _make_host("au-plug-1", "au-plug-1.iot",
                        ip="10.1.90.71", mac="aa:bb:cc:dd:ee:06"),
        ]
        suggestions = suggest_matches("au-plug-1", hosts)
        assert "au-plug-1.iot" in suggestions
        assert "au-plug-1" not in suggestions


# --- TestGetCredentialFields ------------------------------------------------

class TestGetCredentialFields:
    def test_password_type(self):
        host = _make_host("switch1", "switch1", extra={"Password": "secret123"})
        result = get_credential_fields(host, credential_type="password")
        assert result == {"Password": "secret123"}

    def test_snmp_type(self):
        host = _make_host("switch1", "switch1",
                          extra={"SNMP Community": "public"})
        result = get_credential_fields(host, credential_type="snmp")
        assert result == {"SNMP Community": "public"}

    def test_ipmi_type(self):
        host = _make_host("server1", "server1", extra={
            "IPMI Username": "admin",
            "IPMI Password": "hunter2",
        })
        result = get_credential_fields(host, credential_type="ipmi")
        assert result == {"IPMI Username": "admin", "IPMI Password": "hunter2"}

    def test_ipmi_partial(self):
        """If only username is set, only that field is returned."""
        host = _make_host("server1", "server1", extra={
            "IPMI Username": "admin",
        })
        result = get_credential_fields(host, credential_type="ipmi")
        assert result == {"IPMI Username": "admin"}

    def test_default_is_password(self):
        host = _make_host("switch1", "switch1", extra={"Password": "secret"})
        result = get_credential_fields(host)
        assert result == {"Password": "secret"}

    def test_arbitrary_field(self):
        host = _make_host("switch1", "switch1",
                          extra={"Custom Field": "custom_val"})
        result = get_credential_fields(host, field_name="Custom Field")
        assert result == {"Custom Field": "custom_val"}

    def test_missing_field_returns_empty(self):
        host = _make_host("switch1", "switch1", extra={})
        result = get_credential_fields(host, credential_type="password")
        assert result == {}

    def test_blank_field_returns_empty(self):
        host = _make_host("switch1", "switch1", extra={"Password": ""})
        result = get_credential_fields(host, credential_type="password")
        assert result == {}

    def test_unknown_type_raises(self):
        host = _make_host("switch1", "switch1")
        with pytest.raises(ValueError, match="Unknown credential type"):
            get_credential_fields(host, credential_type="bogus")

    def test_missing_arbitrary_field(self):
        host = _make_host("switch1", "switch1", extra={})
        result = get_credential_fields(host, field_name="Nonexistent")
        assert result == {}


# --- TestAvailableCredentialFields ------------------------------------------

class TestAvailableCredentialFields:
    def test_non_empty_fields(self):
        host = _make_host("switch1", "switch1", extra={
            "Password": "secret",
            "SNMP Community": "public",
            "Notes": "",
        })
        available = available_credential_fields(host)
        assert "Password" in available
        assert "SNMP Community" in available
        assert "Notes" not in available

    def test_empty_extra(self):
        host = _make_host("switch1", "switch1", extra={})
        assert available_credential_fields(host) == []

    def test_all_blank(self):
        host = _make_host("switch1", "switch1", extra={
            "Password": "",
            "SNMP Community": "",
        })
        assert available_credential_fields(host) == []
