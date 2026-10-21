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
        assert ('string="/var/log/wifi/%$.name:::secpath-replace%.log"') in conf
        assert 'fileOwner="root" fileGroup="adm"' in conf
        assert 'fileCreateMode="0640" dirCreateMode="0755"' in conf
        assert conf.count("    stop") == 6

    def test_no_10514_transition_input(self):
        # The transition input existed only so switches and wisp could keep
        # logging while they were re-pointed at their net leg :514. All of
        # them were re-pointed on 2026-08-02, so it is gone: every sender
        # now uses the well-known port on the leg it arrives from.
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert "10514" not in conf

    def test_no_leg_no_input(self):
        inv = _inventory([
            _leg("br-net", "02", "10.1.5.1"),
            _leg("br-iot", "03", "10.1.90.1"),
        ])
        conf = generate_rsyslog(inv)["rsyslog.d/remote-logs.conf"]
        assert "remote-wifi" not in conf

    def test_net_leg_is_no_longer_required(self):
        # A 'net' leg used to be mandatory purely because the 10514
        # transition input hard-referenced the remote-net ruleset. With that
        # input gone there is nothing special about 'net'.
        inv = _inventory([_leg("br-iot", "03", "10.1.90.1")])
        conf = generate_rsyslog(inv)["rsyslog.d/remote-logs.conf"]
        assert 'ruleset="remote-iot"' in conf
        assert "remote-net" not in conf

    def test_no_served_legs_fails_loud(self):
        inv = _inventory([_leg("br-tmp", "04", "10.1.1.1")])
        with pytest.raises(ValueError):
            generate_rsyslog(inv)


class TestNetconsole:
    def test_kernel_input_per_served_leg_on_6666(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert ('input(type="imudp" port="6666" address="10.1.4.1" '
                'ruleset="remote-wifi-kernel")') in conf
        assert ('input(type="imudp" port="6666" address="10.1.5.1" '
                'ruleset="remote-net-kernel")') in conf
        assert ('input(type="imudp" port="6666" address="10.1.90.1" '
                'ruleset="remote-iot-kernel")') in conf
        assert conf.count('port="6666"') == 3

    def test_kernel_dynafile_keys_on_the_looked_up_name(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        # same name as the sender's syslog file, so wisp.kernel.log sits
        # beside wisp.log; still secpath-guarded (defence in depth).
        assert ('string="/var/log/wifi/%$.name:::secpath-replace%'
                '.kernel.log"') in conf
        assert conf.count("%$.name:::secpath-replace%.kernel.log") == 3

    def test_kernel_line_template_defined_once_stamps_arrival_and_rawmsg(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('template(name="KernelLine"') == 1
        assert "%timegenerated:::date-rfc3339%" in conf
        # literal backslash-n in the emitted config (rsyslog escape, not Python's)
        assert r"%rawmsg:::drop-last-lf%\n" in conf

    def test_kernel_actions_use_kernel_line_template(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('template="KernelLine"') == 3

    def test_kernel_rulesets_isolated_and_tmp_guest_excluded(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('-kernel") {') == 3
        assert "remote-tmp-kernel" not in conf
        assert "remote-guest-kernel" not in conf


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

    def test_logrotate_untouched_by_netconsole(self):
        # The /var/log/<net>/*.log globs already match *.kernel.log — the
        # kernel files ride the same 1-year-floor stanzas. Pin: no
        # kernel-specific stanza, and exactly one glob per served net.
        rot = generate_rsyslog(_default_inventory())["logrotate.d/remote-logs"]
        assert "kernel" not in rot
        assert rot.count("/var/log/") == 3
        for net in ("wifi", "net", "iot"):
            assert rot.count(f"/var/log/{net}/*.log {{") == 1


class TestRegistry:
    def test_rsyslog_resolves_in_cli_registry(self):
        from gdoc2netcfg.cli import main as cli_main
        func = cli_main._get_generator("rsyslog")
        assert func is generate_rsyslog


def _sender(hostname, *v4s, machine_name=None, sheet_type="Network", mac_suffix="10"):
    return Host(
        machine_name=machine_name or hostname.split(".")[-1],
        hostname=hostname,
        sheet_type=sheet_type,
        interfaces=[
            NetworkInterface(
                name=None if len(v4s) == 1 else f"eth{i}",
                mac=MACAddress.parse(f"02:00:0a:01:{mac_suffix}:{i:02x}"),
                ip_addresses=(IPv4Address(v4),),
                dhcp_name=hostname,
            )
            for i, v4 in enumerate(v4s)
        ],
    )


def _with_senders(*senders):
    inv = _default_inventory()
    return NetworkInventory(site=SITE, hosts=inv.hosts + list(senders))


def _names(inv):
    import json

    table = json.loads(generate_rsyslog(inv)["rsyslog.d/remote-logs.names.json"])
    return {row["index"]: row["value"] for row in table["table"]}, table


class TestSenderNames:
    """Every log file is named by the sheet's hostname for the sending IP —
    never by what the device claims in its header, nor by its PTR."""

    def test_every_ipv4_maps_to_its_hosts_sheet_hostname(self):
        inv = _with_senders(
            _sender("bmc.big-storage", "10.1.5.40", machine_name="big-storage"),
            _sender("au-plug-1.iot", "10.1.90.11", sheet_type="IoT", mac_suffix="11"),
            _sender("sw-core", "10.1.5.2", "10.1.90.2", mac_suffix="12"),
        )
        names, _ = _names(inv)
        assert names["10.1.5.40"] == "bmc.big-storage"
        assert names["10.1.90.11"] == "au-plug-1.iot"
        # a multi-interface host is one device: one file whichever leg sent it
        assert names["10.1.5.2"] == names["10.1.90.2"] == "sw-core"
        # the router's own legs too, so nothing it sends lands in unknown-*
        assert names["10.1.4.1"] == "ten64"

    def test_table_is_complete_and_ipv4_only(self):
        inv = _with_senders(_sender("bmc.big-storage", "10.1.5.40", machine_name="big-storage"))
        names, _ = _names(inv)
        expected = {
            str(iface.ipv4) for host in inv.hosts for iface in host.interfaces
        }
        assert set(names) == expected
        # the inputs are v4-only, so a v6 key could never match
        assert not [ip for ip in names if ":" in ip]

    def test_table_is_an_rsyslog_string_table_with_empty_nomatch(self):
        _, table = _names(_default_inventory())
        assert table["version"] == 1
        assert table["type"] == "string"
        # empty, so the ruleset can substitute unknown-<ip> (see TestRulesetNaming)
        assert table["nomatch"] == ""

    def test_rows_sorted_numerically_for_stable_diffs(self):
        inv = _with_senders(
            _sender("b", "10.1.90.100", mac_suffix="20"),
            _sender("a", "10.1.90.9", mac_suffix="21"),
        )
        _, table = _names(inv)
        import ipaddress
        keys = [ipaddress.IPv4Address(row["index"]) for row in table["table"]]
        assert keys == sorted(keys)

    def test_cross_sheet_mirror_resolves_to_the_network_sheet_host(self):
        """wisp / wisp.wifi are one device recorded on two sheets (CLAUDE.md
        'VLAN-4 infra mirror rows'); the validator accepts the shared IP."""
        inv = _with_senders(
            _sender("wisp", "10.1.4.2", machine_name="wisp", mac_suffix="30"),
            _sender("wisp.wifi", "10.1.4.2", machine_name="wisp",
                    sheet_type="WiFi", mac_suffix="30"),
        )
        names, _ = _names(inv)
        assert names["10.1.4.2"] == "wisp"

    def test_any_other_shared_ip_is_an_assertion_failure(self):
        """Validation rejects two hosts on one IP before data is cached, so
        reaching the generator with one is a bug, not data to name around."""
        inv = _with_senders(
            _sender("sw-old", "10.1.5.31", mac_suffix="40"),
            _sender("sw-new", "10.1.5.31", mac_suffix="41"),
        )
        with pytest.raises(AssertionError, match="10.1.5.31.*sw-new.*sw-old"):
            generate_rsyslog(inv)


class TestRulesetNaming:
    """Both rulesets per net name the file from the generated table."""

    def test_lookup_table_loaded_once_from_the_deployed_path(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count(
            'lookup_table(name="remote-names" '
            'file="/etc/rsyslog.d/remote-logs.names.json" reloadOnHUP="on")'
        ) == 1
        assert conf.index("lookup_table(") < conf.index("ruleset(")

    def test_every_ruleset_looks_up_the_sending_ip(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        # 3 served nets x (syslog + kernel)
        assert conf.count(
            'set $.name = lookup("remote-names", $fromhost-ip);'
        ) == 6

    def test_unknown_sender_gets_its_own_unknown_ip_file(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('if $.name == "" then {') == 6
        assert conf.count('set $.name = "unknown-" & $fromhost-ip;') == 6

    def test_lookup_precedes_the_write_in_each_ruleset(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        for name in ("remote-wifi", "remote-wifi-kernel"):
            block = conf[conf.index(f'ruleset(name="{name}")'):]
            block = block[:block.index("input(")]
            assert block.index("lookup(") < block.index("unknown-") < block.index("action(")

    def test_claimed_hostname_and_ptr_no_longer_name_files(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert "%hostname" not in conf
        assert "$fromhost," not in conf      # the PTR, as opposed to $fromhost-ip
        assert "re_extract" not in conf


class TestSenderNameEdges:
    def test_one_host_with_two_interfaces_on_one_ip_is_one_owner(self):
        """Puck wan+lan (and 14 other live hosts) share one IPv4 inside one
        host; that is one owner, not a collision."""
        inv = _with_senders(
            _sender("puck07.wifi", "10.1.4.107", "10.1.4.107",
                    machine_name="puck07", sheet_type="WiFi", mac_suffix="50"),
        )
        names, table = _names(inv)
        assert names["10.1.4.107"] == "puck07.wifi"
        assert [r["index"] for r in table["table"]].count("10.1.4.107") == 1

    def test_mirror_on_the_routers_own_leg(self):
        """ten64.wifi mirrors the router's br-wifi leg (10.1.4.1)."""
        inv = _with_senders(
            _sender("ten64.wifi", "10.1.4.1", machine_name="ten64",
                    sheet_type="WiFi", mac_suffix="51"),
        )
        names, _ = _names(inv)
        assert names["10.1.4.1"] == "ten64"

    @pytest.mark.parametrize("owners", [
        # different machines on two sheets: a stale row, not a mirror
        [("sw-old", "sw-old", "Network"), ("puck03.wifi", "puck03", "WiFi")],
        # one machine on two sheets but neither is the Network sheet
        [("plug.iot", "plug", "IoT"), ("plug.wifi", "plug", "WiFi")],
        # a mirror plus a second host of the same machine on the same sheet
        [("wisp", "wisp", "Network"), ("wisp.wifi", "wisp", "WiFi"),
         ("bmc.wisp.wifi", "wisp", "WiFi")],
        # a BMC row cloning its parent's IP (same machine, same sheet)
        [("big-storage", "big-storage", "Network"),
         ("bmc.big-storage", "big-storage", "Network")],
    ], ids=["different-machines", "no-network-host", "two-on-one-sheet", "bmc-clone"])
    def test_each_mirror_condition_is_required(self, owners):
        inv = _with_senders(*[
            _sender(hostname, "10.1.5.77", machine_name=machine,
                    sheet_type=sheet, mac_suffix=f"{60 + i}")
            for i, (hostname, machine, sheet) in enumerate(owners)
        ])
        with pytest.raises(AssertionError, match="10.1.5.77"):
            generate_rsyslog(inv)
