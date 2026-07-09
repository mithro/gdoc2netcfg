"""Tests for the pdns internal-auth zone generator (dns-redesign §7).

The internal site zone carries: SOA/NS, insecure NS delegations + glue
for every child net zone (load-bearing — verified V1/V2), site-native
aggregates, CNAME projections, SSHFP/CAA at site natives, and an
optional $INCLUDE for hand-maintained extras. Transit (tfpgas) and wg
zones plus their reverses are separate central-served zone files.
"""

import shutil
import subprocess

import pytest

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.pdns_zones import generate_pdns_internal
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site

DOMAIN = "welland.mithis.com"
SITE = Site(
    name="welland",
    domain=DOMAIN,
    site_octet=1,
    vlans={
        7: VLAN(id=7, name="store", subdomain="store", third_octets=(7,)),
        10: VLAN(
            id=10, name="int", subdomain="int",
            third_octets=(8, 9, 10, 11, 12, 13, 14, 15, 16),
        ),
        21: VLAN(id=21, name="fpgas", subdomain="fpgas", is_global=True),
        121: VLAN(
            id=121, name="tfpgas", subdomain="tfpgas",
            is_transit=True, transit_match=(99, 21),
        ),
    },
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        7: "store",
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int", 16: "int",
    },
)

SERIAL = 1783500000


def _iface(name, mac_suffix, v4, v6=None):
    ips = [IPv4Address(v4)]
    if v6:
        ips.append(IPv6Address(v6, "2404:e80:a137:"))
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(f"aa:bb:cc:dd:ee:{mac_suffix}"),
        ip_addresses=tuple(ips),
        dhcp_name=f"{name}-host" if name else "host",
    )


def _ten64():
    """The site router: per-net gateways + a wg tunnel + tfpgas."""
    return Host(
        machine_name="ten64",
        hostname="ten64",
        interfaces=[
            _iface("br-int", "01", "10.1.10.1", "2404:e80:a137:110::1"),
            _iface("br-store", "02", "10.1.7.1", "2404:e80:a137:107::1"),
            _iface("br-tfpgas", "03", "10.99.21.1", "2404:e80:a137:9921::1"),
            _iface("wg-x1c-work", "04", "10.98.6.1", "2404:e80:a137:9806::1"),
        ],
        aggregate_override=["br-int"],
    )


def _big_storage():
    return Host(
        machine_name="big-storage",
        hostname="big-storage",
        interfaces=[
            _iface("10g1", "11", "10.1.11.154", "2404:e80:a137:111::154"),
            _iface("25g1", "12", "10.1.7.15", "2404:e80:a137:107::15"),
        ],
        sshfp_records=[
            "big-storage IN SSHFP 4 2 "
            "996b3981b870b4b2473e3dbadb3c435a8f2314b6a962a429a78760426bb13ba6"
        ],
    )


def _fpgas_host():
    return Host(
        machine_name="pi4",
        hostname="pi4",
        interfaces=[_iface(None, "21", "10.21.4.1")],
    )


def _inventory(*hosts):
    for host in hosts:
        derive_all_dns_names(host, SITE)
    return NetworkInventory(site=SITE, hosts=list(hosts))


def _generate(*hosts, **kwargs):
    kwargs.setdefault("serial", SERIAL)
    return generate_pdns_internal(_inventory(*hosts), **kwargs)


class TestSiteZone:
    def test_soa_and_ns(self):
        files = _generate(_ten64())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert (
            f"{DOMAIN}. 3600 IN SOA ten64.{DOMAIN}. hostmaster.mithis.com. "
            f"{SERIAL} 10800 3600 604800 300" in zone
        )
        assert f"{DOMAIN}. 3600 IN NS ten64.{DOMAIN}." in zone

    def test_delegations_with_glue_no_ds(self):
        files = _generate(_ten64(), _big_storage())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert f"int.{DOMAIN}. 300 IN NS gw.int.{DOMAIN}." in zone
        assert f"gw.int.{DOMAIN}. 300 IN A 10.1.10.1" in zone
        assert f"gw.int.{DOMAIN}. 300 IN AAAA 2404:e80:a137:110::1" in zone
        assert f"store.{DOMAIN}. 300 IN NS gw.store.{DOMAIN}." in zone
        assert " DS " not in zone

    def test_central_child_zones_delegated_to_self(self):
        """tfpgas/wg zones are served by this same auth — the delegation
        target is the site NS itself (no glue needed)."""
        files = _generate(_ten64())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert f"tfpgas.{DOMAIN}. 300 IN NS ten64.{DOMAIN}." in zone
        assert f"wg.{DOMAIN}. 300 IN NS ten64.{DOMAIN}." in zone

    def test_fpgas_delegated_to_tweed(self):
        files = _generate(_ten64(), _fpgas_host())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert f"fpgas.{DOMAIN}. 300 IN NS gw.fpgas.{DOMAIN}." in zone
        assert f"gw.fpgas.{DOMAIN}. 300 IN A 10.21.0.1" in zone

    def test_site_aggregate_honors_override(self):
        files = _generate(_ten64())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert f"ten64.{DOMAIN}. 300 IN A 10.1.10.1" in zone
        # override excludes br-store from the aggregate
        assert f"ten64.{DOMAIN}. 300 IN A 10.1.7.1" not in zone

    def test_site_natives_and_prefix_forms(self):
        files = _generate(_ten64(), _big_storage())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert f"big-storage.{DOMAIN}. 300 IN A 10.1.11.154" in zone
        assert f"big-storage.{DOMAIN}. 300 IN A 10.1.7.15" in zone
        assert f"ipv4.big-storage.{DOMAIN}. 300 IN A 10.1.11.154" in zone
        assert (
            f"ipv6.big-storage.{DOMAIN}. 300 IN AAAA 2404:e80:a137:111::154" in zone
        )

    def test_cname_projections(self):
        files = _generate(_ten64(), _big_storage())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert (
            f"int.big-storage.{DOMAIN}. 300 IN CNAME big-storage.int.{DOMAIN}." in zone
        )
        assert (
            f"10g1.big-storage.{DOMAIN}. 300 IN CNAME 10g1.big-storage.int.{DOMAIN}."
            in zone
        )
        assert (
            f"ipv4.int.big-storage.{DOMAIN}. 300 IN CNAME "
            f"ipv4.big-storage.int.{DOMAIN}." in zone
        )

    def test_no_net_scoped_records_in_site_zone(self):
        files = _generate(_ten64(), _big_storage())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert f"big-storage.int.{DOMAIN}. 300 IN A" not in zone
        assert f"10g1.big-storage.int.{DOMAIN}. 300 IN A" not in zone

    def test_sshfp_and_caa_at_site_native(self):
        files = _generate(_ten64(), _big_storage())
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert (
            f"big-storage.{DOMAIN}. 300 IN SSHFP 4 2 "
            f"996b3981b870b4b2473e3dbadb3c435a8f2314b6a962a429a78760426bb13ba6" in zone
        )
        assert f'big-storage.{DOMAIN}. 300 IN CAA 0 issue "letsencrypt.org"' in zone
        # never at CNAME owners
        assert f"10g1.big-storage.{DOMAIN}. 300 IN SSHFP" not in zone

    def test_extra_include(self):
        files = _generate(
            _ten64(),
            site_extra_include="/etc/powerdns/zones-internal/welland.mithis.com.extra",
        )
        zone = files[f"zones-internal/{DOMAIN}.zone"]
        assert "$INCLUDE /etc/powerdns/zones-internal/welland.mithis.com.extra" in zone

    def test_no_include_by_default(self):
        files = _generate(_ten64())
        assert "$INCLUDE" not in files[f"zones-internal/{DOMAIN}.zone"]


class TestCentralNetZones:
    def test_wg_zone(self):
        files = _generate(_ten64())
        zone = files[f"zones-internal/wg.{DOMAIN}.zone"]
        assert f"wg.{DOMAIN}. 3600 IN SOA ten64.{DOMAIN}." in zone
        assert f"wg-x1c-work.ten64.wg.{DOMAIN}. 300 IN A 10.98.6.1" in zone
        assert f"ipv4.wg-x1c-work.ten64.wg.{DOMAIN}. 300 IN A 10.98.6.1" in zone

    def test_tfpgas_zone(self):
        files = _generate(_ten64())
        zone = files[f"zones-internal/tfpgas.{DOMAIN}.zone"]
        assert f"br-tfpgas.ten64.tfpgas.{DOMAIN}. 300 IN A 10.99.21.1" in zone

    def test_central_v4_reverses(self):
        files = _generate(_ten64())
        zone = files["zones-internal/98.10.in-addr.arpa.zone"]
        assert (
            "1.6.98.10.in-addr.arpa. 300 IN PTR "
            f"ipv4.wg-x1c-work.ten64.wg.{DOMAIN}." in zone
        )
        zone2 = files["zones-internal/21.99.10.in-addr.arpa.zone"]
        assert (
            "1.21.99.10.in-addr.arpa. 300 IN PTR "
            f"ipv4.br-tfpgas.ten64.tfpgas.{DOMAIN}." in zone2
        )

    def test_central_v6_reverse_slices(self):
        files = _generate(_ten64())
        zone = files["zones-internal/6.0.8.9.7.3.1.a.0.8.e.0.4.0.4.2.ip6.arpa.zone"]
        assert (
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.0.8.9.7.3.1.a.0.8.e.0.4.0.4.2."
            f"ip6.arpa. 300 IN PTR ipv6.wg-x1c-work.ten64.wg.{DOMAIN}." in zone
        )


class TestBindConfig:
    def test_zone_statements(self):
        files = _generate(_ten64())
        conf = files["bind-internal.conf"]
        assert (
            f'zone "{DOMAIN}" {{ type primary; '
            f'file "/etc/powerdns/zones-internal/{DOMAIN}.zone"; }};' in conf
        )
        assert f'zone "wg.{DOMAIN}"' in conf
        assert f'zone "tfpgas.{DOMAIN}"' in conf
        assert 'zone "98.10.in-addr.arpa"' in conf

    def test_zones_dir_kwarg(self):
        files = _generate(_ten64(), zones_dir="/tmp/zones")
        assert f'file "/tmp/zones/{DOMAIN}.zone"' in files["bind-internal.conf"]


@pytest.mark.skipif(
    shutil.which("named-checkzone") is None,
    reason="named-checkzone not installed",
)
class TestZoneSyntax:
    def test_all_zones_load(self, tmp_path):
        files = _generate(_ten64(), _big_storage(), _fpgas_host())
        for fname, content in files.items():
            if not fname.endswith(".zone"):
                continue
            zone_name = fname.split("/")[-1][: -len(".zone")]
            path = tmp_path / fname
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            result = subprocess.run(
                ["named-checkzone", zone_name, str(path)],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, (
                f"{zone_name} failed named-checkzone:\n{result.stdout}{result.stderr}"
            )


class TestContentDerivedSerials:
    """Default serials derive from each zone's own content: regenerating
    unchanged data is byte-identical (no epoch churn in /etc diffs), and
    a record change bumps that zone's serial only. Code revisions matter
    exactly when they change output — by construction."""

    def test_regeneration_is_byte_identical(self):
        files_a = generate_pdns_internal(_inventory(_ten64(), _big_storage()))
        files_b = generate_pdns_internal(_inventory(_ten64(), _big_storage()))
        assert files_a == files_b

    def test_record_change_bumps_only_that_zone(self):
        base = generate_pdns_internal(_inventory(_ten64(), _big_storage()))
        changed_host = _big_storage()
        changed_host.interfaces[0] = _iface(
            "10g1", "11", "10.1.11.99", "2404:e80:a137:111::99"
        )
        changed = generate_pdns_internal(_inventory(_ten64(), changed_host))

        site = f"zones-internal/{DOMAIN}.zone"
        wg = f"zones-internal/wg.{DOMAIN}.zone"
        assert base[site] != changed[site]
        assert base[wg] == changed[wg]

        def _serial(zone_text):
            for line in zone_text.splitlines():
                if " SOA " in line:
                    return int(line.split()[6])
            raise AssertionError("no SOA")

        assert _serial(base[site]) != _serial(changed[site])
        assert _serial(base[wg]) == _serial(changed[wg])

    def test_no_placeholder_leaks(self):
        files = generate_pdns_internal(_inventory(_ten64(), _big_storage()))
        for content in files.values():
            assert "@SERIAL@" not in content

    def test_explicit_serial_still_honored(self):
        files = generate_pdns_internal(
            _inventory(_ten64()), serial=1234567,
        )
        assert " SOA " in files[f"zones-internal/{DOMAIN}.zone"]
        assert "1234567 10800" in files[f"zones-internal/{DOMAIN}.zone"]
