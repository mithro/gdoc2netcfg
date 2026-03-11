"""Tests for the known_hosts generator."""

import base64

from gdoc2netcfg.generators.known_hosts import generate_known_hosts
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import (
    DNSName,
    Host,
    NetworkInterface,
    NetworkInventory,
)
from gdoc2netcfg.models.network import Site

SITE = Site(name="welland", domain="welland.mithis.com")

_RSA_B64 = base64.b64encode(b"test-rsa-key-data").decode()
_ED25519_B64 = base64.b64encode(b"test-ed25519-key-data").decode()


def _iface(ip="10.1.10.1", ipv6=None, mac="AA:BB:CC:DD:EE:01", name=None):
    ip_addrs: list[IPv4Address | IPv6Address] = [IPv4Address(ip)]
    if ipv6:
        ip_addrs.append(IPv6Address(ipv6, "2404:e80:a137:"))
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(mac),
        ip_addresses=tuple(ip_addrs),
    )


def _host(
    hostname, ip, mac="AA:BB:CC:DD:EE:01", dns_names=None,
    ssh_host_keys=None, ipv6=None, interfaces=None,
):
    if interfaces is None:
        interfaces = [_iface(ip=ip, ipv6=ipv6, mac=mac)]
    host = Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=interfaces,
        ssh_host_keys=ssh_host_keys or [],
        dns_names=dns_names or [],
    )
    return host


class TestGenerateKnownHostsEmpty:
    def test_empty_inventory(self):
        inv = NetworkInventory(site=SITE, hosts=[])
        output = generate_known_hosts(inv)
        assert output == ""

    def test_no_ssh_keys(self):
        hosts = [_host("server", "10.1.10.1")]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_known_hosts(inv)
        assert output == ""


class TestGenerateKnownHostsErrors:
    def test_keys_but_no_identifiers_raises(self):
        """Host with SSH keys but no DNS names or IPs is an error."""
        import pytest

        host = Host(
            machine_name="ghost",
            hostname="ghost",
            interfaces=[],
            ssh_host_keys=[f"ghost ssh-rsa {_RSA_B64}"],
            dns_names=[],
        )
        inv = NetworkInventory(site=SITE, hosts=[host])

        with pytest.raises(ValueError, match="no DNS names or IP"):
            generate_known_hosts(inv)


class TestGenerateKnownHostsSingleHost:
    def test_single_host_single_key(self):
        keys = [f"server ssh-rsa {_RSA_B64}"]
        dns = [
            DNSName("server", (IPv4Address("10.1.10.1"),)),
            DNSName(
                "server.welland.mithis.com",
                (IPv4Address("10.1.10.1"),),
                is_fqdn=True,
            ),
        ]
        hosts = [_host("server", "10.1.10.1", dns_names=dns, ssh_host_keys=keys)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_known_hosts(inv)

        lines = output.strip().split("\n")
        assert len(lines) == 1

        # Should contain both DNS names and IP
        parts = lines[0].split(" ", 1)
        host_list = parts[0]
        assert "server" in host_list
        assert "server.welland.mithis.com" in host_list
        assert "10.1.10.1" in host_list

        # Key part
        assert f"ssh-rsa {_RSA_B64}" in lines[0]

    def test_single_host_multiple_keys(self):
        keys = [
            f"server ssh-ed25519 {_ED25519_B64}",
            f"server ssh-rsa {_RSA_B64}",
        ]
        dns = [DNSName("server", (IPv4Address("10.1.10.1"),))]
        hosts = [_host("server", "10.1.10.1", dns_names=dns, ssh_host_keys=keys)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_known_hosts(inv)

        lines = output.strip().split("\n")
        assert len(lines) == 2

    def test_includes_ipv6(self):
        keys = [f"server ssh-rsa {_RSA_B64}"]
        dns = [DNSName("server", (IPv4Address("10.1.10.1"),))]
        hosts = [_host(
            "server", "10.1.10.1",
            ipv6="2404:e80:a137:110a::1",
            dns_names=dns,
            ssh_host_keys=keys,
        )]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_known_hosts(inv)

        assert "2404:e80:a137:110a::1" in output


class TestGenerateKnownHostsMultiInterface:
    def test_multi_interface_includes_all_ips(self):
        keys = [f"server ssh-rsa {_RSA_B64}"]
        interfaces = [
            _iface(ip="10.1.10.1", mac="AA:BB:CC:DD:EE:01", name="eth0"),
            _iface(ip="10.1.20.1", mac="AA:BB:CC:DD:EE:02", name="eth1"),
        ]
        dns = [
            DNSName("server", (IPv4Address("10.1.10.1"),)),
            DNSName("eth0.server", (IPv4Address("10.1.10.1"),)),
            DNSName("eth1.server", (IPv4Address("10.1.20.1"),)),
        ]
        hosts = [_host(
            "server", "10.1.10.1",
            dns_names=dns,
            ssh_host_keys=keys,
            interfaces=interfaces,
        )]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_known_hosts(inv)

        assert "10.1.10.1" in output
        assert "10.1.20.1" in output
        assert "eth0.server" in output
        assert "eth1.server" in output


class TestGenerateKnownHostsOrdering:
    def test_deterministic_ordering(self):
        """Output is sorted by hostname."""
        keys_a = [f"alpha ssh-rsa {_RSA_B64}"]
        keys_z = [f"zulu ssh-rsa {_RSA_B64}"]
        dns_a = [DNSName("alpha", (IPv4Address("10.1.10.1"),))]
        dns_z = [DNSName("zulu", (IPv4Address("10.1.10.2"),))]

        # Add in reverse order
        hosts = [
            _host("zulu", "10.1.10.2", dns_names=dns_z, ssh_host_keys=keys_z),
            _host("alpha", "10.1.10.1", dns_names=dns_a, ssh_host_keys=keys_a),
        ]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_known_hosts(inv)

        lines = output.strip().split("\n")
        assert len(lines) == 2
        # alpha comes before zulu
        assert lines[0].startswith("alpha")
        assert lines[1].startswith("zulu")

    def test_dns_names_not_duplicated(self):
        """IP addresses that appear in dns_names aren't repeated."""
        keys = [f"server ssh-rsa {_RSA_B64}"]
        dns = [DNSName("server", (IPv4Address("10.1.10.1"),))]
        hosts = [_host("server", "10.1.10.1", dns_names=dns, ssh_host_keys=keys)]
        inv = NetworkInventory(site=SITE, hosts=hosts)
        output = generate_known_hosts(inv)

        host_list = output.split(" ")[0]
        ids = host_list.split(",")
        # No duplicate entries
        assert len(ids) == len(set(ids))
