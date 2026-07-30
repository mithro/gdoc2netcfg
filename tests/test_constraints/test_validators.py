"""Tests for constraint validators.

Extracted from the assertions in dnsmasq.py:get_data(), get_mac_info(),
and dhcp_host_config().
"""

from gdoc2netcfg.constraints.validators import (
    validate_cross_record_constraints,
    validate_field_constraints,
    validate_ipv6_consistency,
    validate_record_constraints,
    validate_vlan_consistency,
)
from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site
from gdoc2netcfg.sources.parser import DeviceRecord


def _record(machine="desktop", mac="aa:bb:cc:dd:ee:ff", ip="10.1.10.1", extra=None):
    return DeviceRecord(
        sheet_name="Network", row_number=2,
        machine=machine, mac_address=mac, ip=ip,
        extra=extra or {},
    )


def _host(hostname, interfaces, machine_name=None, sheet_type="Network"):
    return Host(
        machine_name=hostname if machine_name is None else machine_name,
        hostname=hostname,
        sheet_type=sheet_type,
        interfaces=interfaces,
    )


def _iface(name=None, mac="aa:bb:cc:dd:ee:ff", ip="10.1.10.1", dhcp_name="test"):
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(mac),
        ip_addresses=(IPv4Address(ip),),
        dhcp_name=dhcp_name,
    )


# Site with VLANs configured for validator tests
SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    vlans={
        5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
        10: VLAN(id=10, name="int", subdomain="int", third_octets=(8, 9, 10, 11, 12, 13, 14, 15)),
        20: VLAN(id=20, name="roam", subdomain="roam", third_octets=(20,)),
        41: VLAN(id=41, name="sm", subdomain="sm", is_global=True),
    },
)


class TestFieldConstraints:
    def test_valid_record(self):
        result = validate_field_constraints([_record()])
        assert result.is_valid
        assert len(result.violations) == 0

    def test_missing_mac(self):
        result = validate_field_constraints([_record(mac="")])
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "missing_mac"

    def test_missing_machine(self):
        result = validate_field_constraints([_record(machine="")])
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "missing_machine"

    def test_missing_ip(self):
        result = validate_field_constraints([_record(ip="")])
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "missing_ip"

    def test_multiple_missing_fields(self):
        result = validate_field_constraints([_record(mac="", machine="", ip="")])
        assert len(result.warnings) == 3

    def test_record_id_format(self):
        result = validate_field_constraints([_record(mac="")])
        assert result.warnings[0].record_id == "Network:2"


class TestRecordConstraints:
    def test_valid_host(self):
        host = _host("server", [_iface(name="eth0", dhcp_name="eth0-server")])
        result = validate_record_constraints([host], SITE)
        assert result.is_valid

    def test_invalid_dhcp_name(self):
        host = _host("server", [_iface(dhcp_name="bad name!")])
        result = validate_record_constraints([host], SITE)
        assert result.has_errors
        assert result.errors[0].code == "invalid_dhcp_name"

    def test_valid_dhcp_name_with_dots(self):
        host = _host("cam", [_iface(dhcp_name="camera.iot")])
        result = validate_record_constraints([host], SITE)
        assert result.is_valid

    def test_valid_dhcp_name_with_dashes_underscores(self):
        host = _host("srv", [_iface(dhcp_name="eth0-my_server")])
        result = validate_record_constraints([host], SITE)
        assert result.is_valid

    def test_bmc_on_management_network(self):
        """BMC on 10.1.5.X is valid."""
        host = _host("server", [
            _iface(name="bmc", ip="10.1.5.200", dhcp_name="bmc-server"),
        ])
        result = validate_record_constraints([host], SITE)
        assert result.is_valid

    def test_bmc_not_on_management_network(self):
        """BMC on 10.1.10.X is an error."""
        host = _host("server", [
            _iface(name="bmc", ip="10.1.10.200", dhcp_name="bmc-server"),
        ])
        result = validate_record_constraints([host], SITE)
        assert result.has_errors
        assert result.errors[0].code == "bmc_not_management"

    def test_test_hardware_bmc_correct_subnet(self):
        """Test-hardware BMC on 10.41.1.X is valid (global VLAN)."""
        host = _host("board", [
            _iface(name="bmc", ip="10.41.1.200", dhcp_name="bmc-board"),
        ])
        result = validate_record_constraints([host], SITE)
        assert result.is_valid

    def test_test_hardware_bmc_wrong_subnet(self):
        """Test-hardware BMC on 10.41.2.X is an error."""
        host = _host("board", [
            _iface(name="bmc", ip="10.41.2.200", dhcp_name="bmc-board"),
        ])
        result = validate_record_constraints([host], SITE)
        assert result.has_errors
        assert result.errors[0].code == "bmc_wrong_subnet"

    def test_non_bmc_interface_no_check(self):
        """Non-BMC interfaces don't get BMC placement validation."""
        host = _host("server", [
            _iface(name="eth0", ip="10.1.10.200", dhcp_name="eth0-server"),
        ])
        result = validate_record_constraints([host], SITE)
        assert result.is_valid

    def test_bmc_monarto_uses_site_prefix(self):
        """BMC check uses site-derived prefix (10.2.5.X for Monarto)."""
        monarto = Site(
            name="monarto",
            domain="monarto.mithis.com",
            site_octet=2,
            vlans={
                5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
            },
        )
        host = _host("server", [
            _iface(name="bmc", ip="10.2.5.200", dhcp_name="bmc-server"),
        ])
        result = validate_record_constraints([host], monarto)
        assert result.is_valid

        # 10.1.5.X is NOT valid for Monarto
        host2 = _host("server2", [
            _iface(name="bmc", ip="10.1.5.200", dhcp_name="bmc-server2"),
        ])
        result2 = validate_record_constraints([host2], monarto)
        assert result2.has_errors
        assert result2.errors[0].code == "bmc_not_management"


class TestCrossRecordConstraints:
    def test_valid_inventory(self):
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:02", ip="10.1.10.2", dhcp_name="b")]),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.10.1": [(MACAddress.parse("aa:bb:cc:dd:ee:01"), "a")],
                "10.1.10.2": [(MACAddress.parse("aa:bb:cc:dd:ee:02"), "b")],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.is_valid

    def test_mac_duplicate_ip(self):
        """Same MAC on two different IPs is an error."""
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.2", dhcp_name="b")]),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts, ip_to_macs={})
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "mac_duplicate_ip"

    def test_mac_same_ip_ok(self):
        """Same MAC on same IP is fine (e.g., same device listed twice)."""
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="b")]),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts, ip_to_macs={})
        result = validate_cross_record_constraints(inv)
        # MAC→IP check: only one unique IP, so no error
        mac_errors = [v for v in result.errors if v.code == "mac_duplicate_ip"]
        assert len(mac_errors) == 0

    def test_multiple_macs_on_roaming_ip(self):
        """Multiple MACs on a roaming IP (10.1.20.X) is allowed."""
        inv = NetworkInventory(
            site=SITE, hosts=[],
            ip_to_macs={
                "10.1.20.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "laptop-wifi"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "laptop-eth"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        ip_errors = [v for v in result.errors if v.code == "ip_multiple_macs"]
        assert len(ip_errors) == 0

    def test_multiple_macs_on_non_roaming_ip(self):
        """Multiple MACs on a non-roaming IP is an error."""
        inv = NetworkInventory(
            site=SITE, hosts=[],
            ip_to_macs={
                "10.1.10.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "a"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "b"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"

    def test_multiple_macs_on_non_roaming_ip_same_host_ok(self):
        """Multiple MACs on one non-roaming IP is fine when they're both
        interfaces of the SAME host (e.g. a puck's wan + lan ports sharing
        one fixed IP)."""
        hosts = [
            _host("puck12", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.112", dhcp_name="wan-puck12"),
                _iface(mac="aa:bb:cc:dd:ee:02", ip="10.1.4.112", dhcp_name="lan-puck12"),
            ]),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.4.112": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wan-puck12"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "lan-puck12"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        ip_errors = [v for v in result.errors if v.code == "ip_multiple_macs"]
        assert len(ip_errors) == 0

    def test_multiple_macs_on_non_roaming_ip_different_hosts_still_error(self):
        """Multiple MACs on one non-roaming IP from TWO different hosts
        remains an error."""
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:02", ip="10.1.10.1", dhcp_name="b")]),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.10.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "a"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "b"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"

    def test_multiple_macs_on_non_roaming_ip_same_mac_different_hosts_is_error(self):
        """Regression: if two DIFFERENT hosts both list the SAME MAC on one
        non-roaming IP (a sheet copy-paste error), the collision must still
        be flagged. A naive last-writer-wins mac→hostname map would collapse
        this to a single owner and wrongly skip the violation."""
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
            _host("b", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="b")]),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.10.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "a"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "b"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"

    def test_multiple_macs_on_non_roaming_ip_unowned_mac_still_error(self):
        """A MAC absent from any host (unowned) on a non-roaming IP keeps
        the violation even when the other MAC on that IP IS owned by a
        host — an unowned MAC never counts as 'same host'."""
        hosts = [
            _host("a", [_iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.1", dhcp_name="a")]),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.10.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "a"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:99"), "unknown"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"

    def test_multiple_macs_on_roaming_ip_unchanged_different_hosts(self):
        """Roaming range still allows multiple MACs from different hosts,
        regardless of host mapping."""
        hosts = [
            _host("laptop", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.20.1", dhcp_name="laptop-wifi"),
            ]),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.20.1": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "laptop-wifi"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "laptop-eth"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        ip_errors = [v for v in result.errors if v.code == "ip_multiple_macs"]
        assert len(ip_errors) == 0

    def test_cross_sheet_mirror_identical_mac_ip_same_machine_name_ok(self):
        """Cross-sheet mirror: the IP Allocation row (host 'wisp') and the
        wifi-tab formula row (host 'wisp.wifi') record the IDENTICAL
        (MAC, IP) pair under one machine_name ('wisp'). This is a
        deliberate permanent duplication (spec 2026-07-29 wifi-sheet
        tenwrt-site-merge §3b), not a data-entry error."""
        hosts = [
            _host("wisp", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp"),
            ], machine_name="wisp", sheet_type="Network"),
            _host("wisp.wifi", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp.wifi"),
            ], machine_name="wisp", sheet_type="WiFi"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.4.2": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp.wifi"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        ip_errors = [v for v in result.errors if v.code == "ip_multiple_macs"]
        assert len(ip_errors) == 0

    def test_cross_sheet_mirror_different_machine_name_still_error(self):
        """Same MAC+IP pair recorded twice, but the two hosts have
        DIFFERENT machine_names — this is not a recognized mirror and must
        still error."""
        hosts = [
            _host("wisp", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp"),
            ], machine_name="wisp", sheet_type="Network"),
            _host("other.wifi", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="other.wifi"),
            ], machine_name="other", sheet_type="WiFi"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.4.2": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "other.wifi"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"

    def test_cross_sheet_mirror_same_machine_name_different_macs_still_error(self):
        """Same machine_name on both hosts, but the MACs on the IP are
        DIFFERENT — not an identical-pair mirror, and not the single-host
        puck exception either (two distinct hostnames), so this must still
        error."""
        hosts = [
            _host("wisp", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp"),
            ], machine_name="wisp", sheet_type="Network"),
            _host("wisp.wifi", [
                _iface(mac="aa:bb:cc:dd:ee:02", ip="10.1.4.2", dhcp_name="wisp.wifi"),
            ], machine_name="wisp", sheet_type="WiFi"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.4.2": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:02"), "wisp.wifi"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"

    def test_bmc_typo_not_masked_by_coexisting_genuine_mirror(self):
        """Reviewer-verified hole: a same-IP+MAC BMC copy-paste typo must
        still error even when a THIRD, genuinely-mirrored host is also
        present for the same machine_name+MAC+IP. Three hosts, all
        machine_name='wisp', all sharing the identical MAC+IP: 'wisp'
        (Network, real), 'bmc.wisp' (Network, typo — duplicate of wisp),
        'wisp.wifi' (WiFi, genuine mirror). A carve-out that only checks
        "more than one sheet_type present" (2: Network+WiFi) wrongly
        accepts this, because it doesn't notice there are 3 owners for
        only 2 sheet_types (i.e. two hosts sharing one sheet_type, one of
        which must be the typo). The exception must require exactly one
        owning host PER sheet_type."""
        hosts = [
            _host("wisp", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp"),
            ], machine_name="wisp", sheet_type="Network"),
            _host("bmc.wisp", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="bmc-wisp"),
            ], machine_name="wisp", sheet_type="Network"),
            _host("wisp.wifi", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp.wifi"),
            ], machine_name="wisp", sheet_type="WiFi"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.4.2": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "bmc-wisp"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp.wifi"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"

    def test_bmc_typo_not_masked_by_mirror_sharing_mac_on_different_ip(self):
        """Reviewer-verified hole: the same-IP typo ('srv' + 'bmc.srv',
        both Network, identical MAC+IP — a real copy-paste error) must
        still error even when a totally separate host ('srv.wifi', WiFi
        sheet) happens to reuse that MAC on a DIFFERENT IP. A naive
        MAC-global owner lookup leaks 'srv.wifi' into this IP's decision
        (it never actually owns an interface on THIS IP), which — combined
        with the sheet_type-span check — would wrongly suppress the typo's
        error. Owner sets for the mirror exception must be derived only
        from hosts that own an interface on the COLLIDING IP.

        Note: 'srv.wifi' reusing MAC A on a different IP also legitimately
        trips the separate mac_duplicate_ip check (a MAC on two distinct
        IPs) — expected and irrelevant here. This test isolates whether
        ip_multiple_macs specifically still fires for the same-IP typo,
        filtering by code rather than asserting on error order."""
        hosts = [
            _host("srv", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.50", dhcp_name="srv"),
            ], machine_name="srv", sheet_type="Network"),
            _host("bmc.srv", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.50", dhcp_name="bmc-srv"),
            ], machine_name="srv", sheet_type="Network"),
            _host("srv.wifi", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.20.7", dhcp_name="srv.wifi"),
            ], machine_name="srv", sheet_type="WiFi"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.10.50": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "srv"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "bmc-srv"),
                ],
                "10.1.20.7": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "srv.wifi"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        ip_errors = [v for v in result.errors if v.code == "ip_multiple_macs"]
        assert len(ip_errors) == 1

    def test_bmc_split_same_machine_name_same_sheet_type_mac_ip_copy_paste_still_error(self):
        """A BMC row legitimately shares machine_name with its parent (see
        CLAUDE.md 'BMC Handling': both 'big-storage' and 'bmc.big-storage'
        carry machine_name='big-storage'), but both come from the SAME
        sheet ('Network') — there is no cross-sheet signal here. If a
        copy-paste error gave the BMC row its parent's exact MAC+IP, that
        must still be flagged: same machine_name alone is not sufficient
        for the mirror carve-out, only a genuine cross-sheet mirror is."""
        hosts = [
            _host("big-storage", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.50", dhcp_name="big-storage"),
            ], machine_name="big-storage", sheet_type="Network"),
            _host("bmc.big-storage", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.10.50", dhcp_name="bmc-big-storage"),
            ], machine_name="big-storage", sheet_type="Network"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.10.50": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "big-storage"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "bmc-big-storage"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert result.has_errors
        assert result.errors[0].code == "ip_multiple_macs"


IPV6_SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    ipv6_prefixes=[
        IPv6Prefix(prefix="2404:e80:a137:", enabled=True),
        IPv6Prefix(prefix="2001:470:82b3:", enabled=False),
    ],
)


def _ipv6_record(ip="10.1.10.1", extra=None, machine="desktop", iface="eth0"):
    return DeviceRecord(
        sheet_name="Network", row_number=99,
        machine=machine, mac_address="aa:bb:cc:dd:ee:ff", ip=ip,
        interface=iface,
        extra=extra or {},
    )


class TestIPv6Consistency:
    def test_matching_ipv6_no_violations(self):
        """Spreadsheet IPv6 matching the algorithm produces no violations."""
        record = _ipv6_record(extra={
            "IPv6 A": "2404:e80:a137:110::1",
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert result.is_valid
        assert len(result.violations) == 0

    def test_mismatched_ipv6_is_error(self):
        """Spreadsheet IPv6 differing from algorithm is an error."""
        record = _ipv6_record(extra={
            "IPv6 A": "2404:e80:a137:110::99",  # Algorithm expects ::1
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert result.has_errors
        assert result.errors[0].code == "ipv6_mismatch"

    def test_disabled_prefix_skipped(self):
        """IPv6 B using disabled prefix is silently skipped."""
        record = _ipv6_record(extra={
            "IPv6 A": "2404:e80:a137:110::1",
            "IPv6 B": "2001:470:82b3:110::1",
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert result.is_valid
        assert len(result.violations) == 0

    def test_unknown_prefix_is_warning(self):
        """IPv6 with unrecognized prefix produces a warning."""
        record = _ipv6_record(extra={
            "IPv6 A": "fd00:1234:5678:110::1",
        })
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "ipv6_unknown_prefix"

    def test_no_ipv6_columns_no_violations(self):
        """Records without IPv6 columns produce no violations."""
        record = _ipv6_record(extra={"Location": "rack-1"})
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.violations) == 0

    def test_empty_ipv6_value_no_violation(self):
        """Empty IPv6 column value is not a violation."""
        record = _ipv6_record(extra={"IPv6 A": ""})
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.violations) == 0

    def test_non_mappable_ip_with_ipv6_warns(self):
        """Public IP with spreadsheet IPv6 warns (no algorithmic mapping)."""
        record = _ipv6_record(
            ip="87.121.95.37",
            extra={"IPv6 A": "2404:e80:a137:110::1"},
        )
        result = validate_ipv6_consistency([record], IPV6_SITE)
        assert len(result.warnings) == 1
        assert result.warnings[0].code == "ipv6_no_algorithmic"


# VLAN consistency site: needs VLANs configured for ip_to_vlan_id
VLAN_SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    vlans={
        5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
        10: VLAN(id=10, name="int", subdomain="int", third_octets=(8, 9, 10, 11, 12, 13, 14, 15)),
        20: VLAN(id=20, name="roam", subdomain="roam", third_octets=(20,)),
    },
)


class TestVlanConsistency:
    def test_matching_vlan_no_violations(self):
        """VLAN column matching IP-derived VLAN produces no violations."""
        record = _record(ip="10.1.10.1", extra={"VLAN": "10"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.is_valid

    def test_mismatched_vlan_is_error(self):
        """VLAN column differing from IP-derived VLAN is an error."""
        record = _record(ip="10.1.10.1", extra={"VLAN": "20"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.has_errors
        assert result.errors[0].code == "vlan_mismatch"

    def test_skips_empty_vlan(self):
        """Empty VLAN column is not checked."""
        record = _record(ip="10.1.10.1", extra={"VLAN": ""})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.is_valid

    def test_skips_na_vlan(self):
        """Non-numeric VLAN value 'N/A' is skipped."""
        record = _record(ip="10.1.10.1", extra={"VLAN": "N/A"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.is_valid

    def test_skips_q_vlan(self):
        """Non-numeric VLAN value 'Q' is skipped."""
        record = _record(ip="10.1.10.1", extra={"VLAN": "Q"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.is_valid

    def test_no_vlan_column(self):
        """Records without a VLAN column produce no violations."""
        record = _record(ip="10.1.10.1")
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.is_valid

    def test_no_ip_skipped(self):
        """Records without an IP are skipped."""
        record = _record(ip="", extra={"VLAN": "10"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.is_valid

    def test_unknown_ip_no_error(self):
        """IP that doesn't map to any VLAN does not produce mismatch error."""
        record = _record(ip="10.1.50.1", extra={"VLAN": "10"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        # derived_vlan is None, so no mismatch
        assert result.is_valid

    def test_net_vlan_match(self):
        """VLAN 5 on 10.1.5.X is valid."""
        record = _record(ip="10.1.5.100", extra={"VLAN": "5"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.is_valid

    def test_net_vlan_mismatch(self):
        """VLAN 10 on 10.1.5.X (actually VLAN 5) is an error."""
        record = _record(ip="10.1.5.100", extra={"VLAN": "10"})
        result = validate_vlan_consistency([record], VLAN_SITE)
        assert result.has_errors
        assert result.errors[0].code == "vlan_mismatch"


class TestMacLessAndCrossHostDuplicates:
    """MAC-less (DNS-only) interfaces must not trip the MAC-keyed
    validators, and cross-host IP sharing must error even without MACs
    (the stale-row class the DHCP-keyed check missed: sw-netgear-m7300
    rows left behind after the m4300 took over their addresses)."""

    def test_macless_interfaces_do_not_collide_as_mac_none(self):
        from gdoc2netcfg.constraints.validators import (
            validate_cross_record_constraints,
        )
        from gdoc2netcfg.models.addressing import IPv4Address
        from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory

        hosts = [
            Host(
                machine_name=f"h{i}",
                hostname=f"h{i}",
                interfaces=[
                    NetworkInterface(
                        name="wg0",
                        mac=None,
                        ip_addresses=(IPv4Address(f"10.1.10.{i}"),),
                        dhcp_name=f"wg0-h{i}",
                    )
                ],
            )
            for i in (1, 2)
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        result = validate_cross_record_constraints(inv)
        assert not [v for v in result.errors if v.code == "mac_duplicate_ip"]

    def test_cross_host_shared_ip_errors_without_macs(self):
        from gdoc2netcfg.constraints.validators import (
            validate_cross_record_constraints,
        )
        from gdoc2netcfg.models.addressing import IPv4Address
        from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory

        hosts = [
            Host(
                machine_name=name,
                hostname=name,
                interfaces=[
                    NetworkInterface(
                        name=None,
                        mac=None,
                        ip_addresses=(IPv4Address("10.1.5.31"),),
                        dhcp_name=name,
                    )
                ],
            )
            for name in ("sw-old", "sw-new")
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        result = validate_cross_record_constraints(inv)
        errors = [v for v in result.errors if v.code == "ip_multiple_hosts"]
        assert len(errors) == 1
        assert "sw-old" in errors[0].message and "sw-new" in errors[0].message

    def test_cross_host_shared_roaming_ip_is_exempt(self):
        """Same roaming-range exemption as ip_multiple_macs: pool
        addresses legitimately move between devices."""
        from gdoc2netcfg.constraints.validators import (
            validate_cross_record_constraints,
        )
        from gdoc2netcfg.models.addressing import IPv4Address
        from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory

        hosts = [
            Host(
                machine_name=name,
                hostname=name,
                interfaces=[
                    NetworkInterface(
                        name="wlan0",
                        mac=None,
                        ip_addresses=(IPv4Address("10.1.20.7"),),
                        dhcp_name=name,
                    )
                ],
            )
            for name in ("laptop", "phone")
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        result = validate_cross_record_constraints(inv)
        assert not [v for v in result.errors if v.code == "ip_multiple_hosts"]

    def test_same_host_shared_ip_is_fine(self):
        """eth0+wlan0 sharing one IP on ONE host is the roaming pattern
        (VirtualInterface grouping) — never an error."""
        from gdoc2netcfg.constraints.validators import (
            validate_cross_record_constraints,
        )
        from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
        from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory

        host = Host(
            machine_name="lap",
            hostname="lap",
            interfaces=[
                NetworkInterface(
                    name="eth0",
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:01"),
                    ip_addresses=(IPv4Address("10.1.20.5"),),
                    dhcp_name="eth0-lap",
                ),
                NetworkInterface(
                    name="wlan0",
                    mac=MACAddress.parse("aa:bb:cc:dd:ee:02"),
                    ip_addresses=(IPv4Address("10.1.20.5"),),
                    dhcp_name="wlan0-lap",
                ),
            ],
        )
        inv = NetworkInventory(site=SITE, hosts=[host])
        result = validate_cross_record_constraints(inv)
        assert not [v for v in result.errors if v.code == "ip_multiple_hosts"]

    def test_cross_sheet_mirror_is_exempt(self):
        """The same cross-sheet-mirror carve-out as ip_multiple_macs: an IP
        Allocation row ('wisp') and its wifi-tab formula row ('wisp.wifi')
        record the identical MAC+IP under one machine_name — permanent by
        design, so ip_multiple_hosts must not fire either."""
        from gdoc2netcfg.constraints.validators import (
            validate_cross_record_constraints,
        )
        from gdoc2netcfg.models.addressing import MACAddress
        from gdoc2netcfg.models.host import NetworkInventory

        hosts = [
            _host("wisp", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp"),
            ], machine_name="wisp", sheet_type="Network"),
            _host("wisp.wifi", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.4.2", dhcp_name="wisp.wifi"),
            ], machine_name="wisp", sheet_type="WiFi"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.4.2": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "wisp.wifi"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert not result.errors

    def test_same_sheet_machine_name_split_still_errors(self):
        """A same-sheet machine_name split (e.g. a BMC row copy-pasted with
        its parent's exact MAC+IP, both sheet_type 'Network') is NOT a
        mirror — ip_multiple_hosts must still fire."""
        from gdoc2netcfg.constraints.validators import (
            validate_cross_record_constraints,
        )
        from gdoc2netcfg.models.addressing import MACAddress
        from gdoc2netcfg.models.host import NetworkInventory

        hosts = [
            _host("big-storage", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.5.31",
                       dhcp_name="big-storage"),
            ], machine_name="big-storage", sheet_type="Network"),
            _host("bmc.big-storage", [
                _iface(mac="aa:bb:cc:dd:ee:01", ip="10.1.5.31",
                       dhcp_name="bmc.big-storage"),
            ], machine_name="big-storage", sheet_type="Network"),
        ]
        inv = NetworkInventory(
            site=SITE, hosts=hosts,
            ip_to_macs={
                "10.1.5.31": [
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "big-storage"),
                    (MACAddress.parse("aa:bb:cc:dd:ee:01"), "bmc.big-storage"),
                ],
            },
        )
        result = validate_cross_record_constraints(inv)
        assert [v for v in result.errors if v.code == "ip_multiple_hosts"]
