"""Tests for the pdns external-auth zone generator (dns-redesign §7).

The public view is ONE flat zone: every in-domain name (site and net
scoped alike) as native records with RFC1918 IPv4s replaced by the
site's public address and global IPv6 as-is. No CNAMEs, no child-zone
delegations (leaves aren't publicly reachable), no internal addresses.
NS = the Rollernet secondaries (V4 finding: they are the public face;
ten64 is a hidden primary they AXFR from).
"""

import shutil
import subprocess

import pytest

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.pdns_external import generate_pdns_external
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import IPv6Prefix, Site

DOMAIN = "welland.mithis.com"
PUBLIC_V4 = "87.121.95.37"
SITE = Site(
    name="welland",
    domain=DOMAIN,
    site_octet=1,
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    network_subdomains={
        7: "store",
        8: "int", 9: "int", 10: "int", 11: "int",
        12: "int", 13: "int", 14: "int", 15: "int", 16: "int",
    },
    public_ipv4=PUBLIC_V4,
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


def _ten64():
    """Router with a public WAN interface and the apex alt name."""
    return Host(
        machine_name="ten64",
        hostname="ten64",
        interfaces=[
            _iface("br-raw", "01", "10.1.0.1", "2404:e80:a137:100::1"),
            _iface("eth0", "02", "87.121.95.37"),
        ],
        alt_names=[DOMAIN],
        aggregate_override=["br-raw"],
    )


def _inventory(*hosts):
    for host in hosts:
        derive_all_dns_names(host, SITE)
    return NetworkInventory(site=SITE, hosts=list(hosts))


def _generate(*hosts, **kwargs):
    kwargs.setdefault("serial", SERIAL)
    return generate_pdns_external(_inventory(*hosts), **kwargs)


class TestExternalZone:
    def test_soa_and_rollernet_ns(self):
        files = _generate(_big_storage())
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert (
            f"{DOMAIN}. 3600 IN SOA {DOMAIN}. hostmaster.mithis.com. "
            f"{SERIAL} 10800 3600 604800 300" in zone
        )
        assert f"{DOMAIN}. 3600 IN NS ns1.rollernet.us." in zone
        assert f"{DOMAIN}. 3600 IN NS ns2.rollernet.us." in zone

    def test_apex_record_from_alt_name(self):
        files = _generate(_ten64())
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert f"{DOMAIN}. 300 IN A {PUBLIC_V4}" in zone
        assert f"{DOMAIN}. 300 IN AAAA 2404:e80:a137:100::1" in zone

    def test_rfc1918_transformed_ipv6_kept(self):
        files = _generate(_big_storage())
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert f"big-storage.{DOMAIN}. 300 IN A {PUBLIC_V4}" in zone
        assert f"big-storage.{DOMAIN}. 300 IN AAAA 2404:e80:a137:111::154" in zone
        assert "10.1.11.154" not in zone
        assert "10.1.7.15" not in zone

    def test_net_scoped_names_flat_native(self):
        files = _generate(_big_storage())
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert f"big-storage.int.{DOMAIN}. 300 IN A {PUBLIC_V4}" in zone
        assert (
            f"big-storage.int.{DOMAIN}. 300 IN AAAA 2404:e80:a137:111::154" in zone
        )
        assert f"10g1.big-storage.int.{DOMAIN}. 300 IN A {PUBLIC_V4}" in zone

    def test_no_cnames_or_delegations(self):
        files = _generate(_big_storage(), _ten64())
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert " CNAME " not in zone
        assert f" IN NS gw." not in zone

    def test_public_v4_deduplicated_per_name(self):
        """Both RFC1918 addresses map to the same public IP — one A each."""
        files = _generate(_big_storage())
        zone = files[f"zones-external/{DOMAIN}.zone"]
        line = f"big-storage.{DOMAIN}. 300 IN A {PUBLIC_V4}"
        assert zone.splitlines().count(line) == 1

    def test_sshfp_caa_at_site_native_only(self):
        files = _generate(_big_storage())
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert f"big-storage.{DOMAIN}. 300 IN SSHFP 4 2" in zone
        assert f'big-storage.{DOMAIN}. 300 IN CAA 0 issue "letsencrypt.org"' in zone
        assert f"10g1.big-storage.{DOMAIN}. 300 IN SSHFP" not in zone
        assert "in-addr.arpa" not in zone

    def test_extra_include(self):
        files = _generate(
            _big_storage(),
            site_extra_include="/etc/powerdns/zones-external/welland.mithis.com.extra",
        )
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert (
            "$INCLUDE /etc/powerdns/zones-external/welland.mithis.com.extra" in zone
        )

    def test_no_public_ip_returns_empty(self):
        site = Site(name="x", domain=DOMAIN, site_octet=1)
        inv = NetworkInventory(site=site, hosts=[])
        assert generate_pdns_external(inv, serial=SERIAL) == {}


class TestBindConfig:
    def test_zone_statement(self):
        files = _generate(_big_storage())
        conf = files["bind-external.conf"]
        assert (
            f'zone "{DOMAIN}" {{ type primary; '
            f'file "/etc/powerdns/zones-external/{DOMAIN}.zone"; }};' in conf
        )


@pytest.mark.skipif(
    shutil.which("named-checkzone") is None,
    reason="named-checkzone not installed",
)
class TestZoneSyntax:
    def test_zone_loads(self, tmp_path):
        files = _generate(_big_storage(), _ten64())
        path = tmp_path / f"{DOMAIN}.zone"
        path.write_text(files[f"zones-external/{DOMAIN}.zone"])
        result = subprocess.run(
            ["named-checkzone", DOMAIN, str(path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"failed named-checkzone:\n{result.stdout}{result.stderr}"
        )


class TestCgnatOmission:
    def test_cgnat_never_published(self):
        host = Host(
            machine_name="x1c-work",
            hostname="x1c-work",
            interfaces=[
                _iface("wifi", "01", "10.1.20.51", "2404:e80:a137:120::51"),
                _iface("tailscale0", "02", "100.110.251.12"),
            ],
        )
        files = _generate(host)
        zone = files[f"zones-external/{DOMAIN}.zone"]
        assert "100.110.251.12" not in zone
        # the site name still gets the public transform of the RFC1918 addr
        assert f"x1c-work.{DOMAIN}. 300 IN A {PUBLIC_V4}" in zone


class TestDuplicateRecordLines:
    """Two rows with one interface name produce DISTINCT private A
    records but the SAME public A (both map to the site IPv4) —
    external must dedupe identical lines (pdns rejects rrset dupes)."""

    def test_same_named_interfaces_dedupe_public_a(self):
        host = Host(
            machine_name="sw3",
            hostname="sw3",
            interfaces=[
                _iface("manage", "31", "10.1.10.24", "2404:e80:a137:110::24"),
                _iface("manage", "32", "10.1.10.31", "2404:e80:a137:110::31"),
            ],
        )
        files = _generate(_ten64(), host)
        zone = files[f"zones-external/{DOMAIN}.zone"]
        line = f"manage.sw3.{DOMAIN}. 300 IN A 87.121.95.37"
        # exact-line count: substring count would also match the
        # ipv4.-prefixed record containing this line as a suffix
        assert zone.splitlines().count(line) == 1
