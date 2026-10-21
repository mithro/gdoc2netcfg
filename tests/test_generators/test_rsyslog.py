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
            'lookup_table(name="remote-names"\n'
            '             file="/etc/rsyslog.d/remote-logs.names.json" '
            'reloadOnHUP="on")'
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


ALERTS = dict(
    alert_mail_to="servers+ten64.welland@mithis.com",
    alert_mail_from="rsyslog@ten64.welland.mithis.com",
    alert_smtp_server="127.0.0.1",
    alert_smtp_port="25",
    alert_interval="60",
)


def _conf(**kwargs):
    return generate_rsyslog(_default_inventory(), **kwargs)["rsyslog.d/remote-logs.conf"]


def _ruleset(conf, name):
    block = conf[conf.index(f'ruleset(name="{name}")'):]
    return block[:block.index("\ninput(")]


class TestAlerts:
    def test_no_alert_settings_means_no_alerts(self):
        conf = _conf()
        assert "ommail" not in conf

    def test_partial_alert_settings_fail_loud(self):
        partial = dict(ALERTS)
        del partial["alert_smtp_port"]
        with pytest.raises(ValueError, match="alert_smtp_port"):
            _conf(**partial)

    def test_interval_must_be_a_positive_integer(self):
        with pytest.raises(ValueError, match="alert_interval"):
            _conf(**{**ALERTS, "alert_interval": "soon"})

    def test_ommail_loaded_once(self):
        assert _conf(**ALERTS).count('module(load="ommail")') == 1

    def test_bmc_health_critical_or_warning_mails_from_every_syslog_ruleset(self):
        conf = _conf(**ALERTS)
        for net in ("wifi", "net", "iot"):
            block = _ruleset(conf, f"remote-{net}")
            assert ('if $msg contains "Health EventLog" and\n'
                    '       ($msg contains "| Critical |" or '
                    '$msg contains "| Warning |") then {') in block
            assert 'subject.template="AlertSubjectBmc"' in block

    def test_unknown_sender_mails_from_every_ruleset(self):
        conf = _conf(**ALERTS)
        for name in ("remote-net", "remote-net-kernel", "remote-iot-kernel"):
            block = _ruleset(conf, name)
            assert 'if $.name startswith "unknown-" then {' in block
            assert 'subject.template="AlertSubjectUnknown"' in block

    def test_kernel_rulesets_carry_no_bmc_rule(self):
        block = _ruleset(_conf(**ALERTS), "remote-net-kernel")
        assert "Health EventLog" not in block

    def test_mail_actions_use_the_configured_relay_and_rate_limit(self):
        block = _ruleset(_conf(**ALERTS), "remote-net")
        assert block.count('server="127.0.0.1" port="25"') == 2
        assert block.count('mailfrom="rsyslog@ten64.welland.mithis.com"') == 2
        assert block.count('mailto="servers+ten64.welland@mithis.com"') == 2
        assert block.count('action.execOnlyOnceEveryInterval="60"') == 2

    def test_mail_actions_have_their_own_queue(self):
        """An SMTP outage must never stall the file write (probe: the
        line is still written with the relay down)."""
        block = _ruleset(_conf(**ALERTS), "remote-net")
        assert block.count('queue.type="LinkedList"') == 2

    def test_file_is_written_before_any_mail_is_attempted(self):
        block = _ruleset(_conf(**ALERTS), "remote-net")
        assert block.index('type="omfile"') < block.index('type="ommail"')

    def test_bmc_subject_names_the_device_severity_and_event(self):
        conf = _conf(**ALERTS)
        assert conf.count('template(name="AlertSubjectBmc"') == 1
        assert "%$.name%" in conf[conf.index('template(name="AlertSubjectBmc"'):]


class TestAlertsFromToml:
    def _config(self, tmp_path, alert_lines):
        import textwrap
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "ten64,02:00:0a:01:05:01,10.1.5.1,br-net\n"
            "bmc.big-storage,aa:bb:cc:dd:ee:01,10.1.5.150,\n"
        )
        (cache_dir / "vlan_allocations.csv").write_text(
            "VLAN,Name,IP Range,Netmask,CIDR,,,Color,For\n"
            "5,net,10.X.5.X,255.255.255.0,/24,,,,Network\n"
        )
        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"
            site_octet = 1

            [sheets]
            network = "https://example.com/not-used"
            vlan_allocations = "https://example.com/not-used-either"

            [cache]
            directory = "{cache_dir}"

            [ipv6]
            prefixes = ["2001:db8:1:"]

            [generators]
            enabled = []

            [generators.rsyslog]
            output_dir = "etc"
        """) + alert_lines)
        return config

    def test_toml_alert_keys_reach_the_generator(self, tmp_path, capsys):
        from gdoc2netcfg.cli.main import main
        config = self._config(tmp_path, (
            'alert_mail_to = "servers+test@example.com"\n'
            'alert_mail_from = "rsyslog@test.example.com"\n'
            'alert_smtp_server = "127.0.0.1"\n'
            "alert_smtp_port = 25\n"        # toml integers are accepted
            "alert_interval = 60\n"
        ))
        assert main(["-c", str(config), "generate", "--stdout", "rsyslog"]) == 0
        out = capsys.readouterr().out
        assert 'mailto="servers+test@example.com"' in out
        assert 'server="127.0.0.1" port="25"' in out
        assert 'action.execOnlyOnceEveryInterval="60"' in out

    def test_no_alert_keys_no_mail(self, tmp_path, capsys):
        from gdoc2netcfg.cli.main import main
        config = self._config(tmp_path, "")
        assert main(["-c", str(config), "generate", "--stdout", "rsyslog"]) == 0
        assert "ommail" not in capsys.readouterr().out


class TestAlertSettingTypes:
    @pytest.mark.parametrize("key,value", [
        ("alert_smtp_port", "0"), ("alert_smtp_port", 70000),
        ("alert_smtp_port", True), ("alert_interval", 0), ("alert_interval", "-5"),
    ])
    def test_bad_numbers_fail_loud(self, key, value):
        with pytest.raises(ValueError, match=f"{key} must be a whole number"):
            _conf(**{**ALERTS, key: value})

    def test_integers_accepted(self):
        conf = _conf(**{**ALERTS, "alert_smtp_port": 25, "alert_interval": 60})
        assert 'port="25"' in conf
        assert 'action.execOnlyOnceEveryInterval="60"' in conf
