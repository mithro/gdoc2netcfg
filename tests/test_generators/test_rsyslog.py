"""Tests for the rsyslog remote-capture generator."""

import pytest

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.rsyslog import generate_rsyslog
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    vlans={
        1: VLAN(id=1, name="tmp", subdomain="tmp", third_octets=(1,)),
        4: VLAN(id=4, name="wifi", subdomain="wifi", third_octets=(4,)),
        5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
        90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90, 91)),
        99: VLAN(id=99, name="guest", subdomain="guest", third_octets=(99,)),
    },
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    # LOAD-BEARING: ip_to_net() classifies site-octet addresses via
    # network_subdomains (NOT vlans) — without this map _leaf_gateways
    # returns {} and every test fails pointing at the wrong place.
    network_subdomains={1: "tmp", 4: "wifi", 5: "net",
                        90: "iot", 91: "iot", 99: "guest"},
)


def _leg(name, suffix, v4, v6=None):
    ips = [IPv4Address(v4)]
    if v6:
        ips.append(IPv6Address(v6, "2404:e80:a137:"))
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(f"02:00:0a:01:00:{suffix}"),
        ip_addresses=tuple(ips),
        dhcp_name=f"{name}-ten64",
    )


def _inventory(interfaces):
    router = Host(machine_name="ten64", hostname="ten64", interfaces=interfaces)
    derive_all_dns_names(router, SITE)
    return NetworkInventory(site=SITE, hosts=[router])


def _default_inventory():
    return _inventory([
        _leg("br-wifi", "01", "10.1.4.1", "2404:e80:a137:104::1"),
        _leg("br-net", "02", "10.1.5.1"),
        _leg("br-iot", "03", "10.1.90.1"),
        _leg("br-tmp", "04", "10.1.1.1"),
        _leg("br-guest", "05", "10.1.99.1"),
    ])


class TestRsyslogConf:
    def test_one_input_per_served_leg_on_514(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert ('input(type="imudp" port="514" address="10.1.4.1" '
                'ruleset="remote-wifi")') in conf
        assert ('input(type="imudp" port="514" address="10.1.5.1" '
                'ruleset="remote-net")') in conf
        assert ('input(type="imudp" port="514" address="10.1.90.1" '
                'ruleset="remote-iot")') in conf

    def test_tmp_and_guest_excluded(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert "10.1.1.1" not in conf
        assert "10.1.99.1" not in conf
        assert "remote-tmp" not in conf
        assert "remote-guest" not in conf

    def test_v4_only_inputs(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert "2404:e80:a137:104::1" not in conf

    def test_single_imudp_module_load(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('module(load="imudp")') == 1

    def test_ruleset_writes_secpath_dynafile_and_stops(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert ('string="/var/log/wifi/%hostname:::secpath-replace%.log"') in conf
        assert 'fileOwner="root" fileGroup="adm"' in conf
        assert 'fileCreateMode="0640" dirCreateMode="0755"' in conf
        assert conf.count("    stop") == 3

    def test_transition_input_10514_targets_remote_net(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert 'input(type="imudp" port="10514" ruleset="remote-net")' in conf

    def test_no_leg_no_input(self):
        inv = _inventory([
            _leg("br-net", "02", "10.1.5.1"),
            _leg("br-iot", "03", "10.1.90.1"),
        ])
        conf = generate_rsyslog(inv)["rsyslog.d/remote-logs.conf"]
        assert "remote-wifi" not in conf

    def test_no_net_leg_fails_loud(self):
        inv = _inventory([_leg("br-iot", "03", "10.1.90.1")])
        with pytest.raises(ValueError, match="net"):
            generate_rsyslog(inv)

    def test_no_served_legs_fails_loud(self):
        inv = _inventory([_leg("br-tmp", "04", "10.1.1.1")])
        with pytest.raises(ValueError):
            generate_rsyslog(inv)


class TestLogrotate:
    def test_stanza_per_served_net_with_year_floor_policy(self):
        rot = generate_rsyslog(_default_inventory())["logrotate.d/remote-logs"]
        for net in ("wifi", "net", "iot"):
            assert f"/var/log/{net}/*.log {{" in rot
        # the 1-year-floor policy, verbatim from the retired etc/logrotate-tasmota
        # (per-stanza counts, not bare `in` — the header comment mentions some
        # of these words, so substring presence alone proves nothing)
        assert rot.count("rotate 400") == 3
        for directive in ("daily", "compress", "delaycompress",
                          "missingok", "notifempty"):
            assert rot.count(f"\n    {directive}\n") == 3, directive
        assert rot.count("/usr/lib/rsyslog/rsyslog-rotate") == 3

    def test_no_stanza_for_excluded_or_legless_nets(self):
        rot = generate_rsyslog(_default_inventory())["logrotate.d/remote-logs"]
        assert "/var/log/tmp/" not in rot
        assert "/var/log/guest/" not in rot


class TestRegistry:
    def test_rsyslog_resolves_in_cli_registry(self):
        from gdoc2netcfg.cli import main as cli_main
        func = cli_main._get_generator("rsyslog")
        assert func is generate_rsyslog
