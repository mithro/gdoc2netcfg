"""Tests for the SSHFP supplement."""

import base64
from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.sshfp import (
    derive_sshfp_from_host_keys,
    enrich_hosts_with_sshfp,
    load_sshfp_cache,
    save_sshfp_cache,
    scan_sshfp,
)

# A minimal valid base64 key blob for testing. The actual key type doesn't
# matter for testing the scan pipeline — we just need it to be valid base64
# so derive_sshfp_from_host_keys can decode and hash it.
_TEST_KEY_BLOB = base64.b64encode(b"test-ssh-rsa-key-blob").decode()
_TEST_ED25519_BLOB = base64.b64encode(b"test-ed25519-key-blob").decode()


def _make_host(hostname, ip):
    return Host(
        machine_name=hostname,
        hostname=hostname,
        interfaces=[
            NetworkInterface(
                name=None,
                mac=MACAddress.parse("aa:bb:cc:dd:ee:ff"),
                ip_addresses=(IPv4Address(ip),),
            )
        ],
    )


def _expected_sshfp(hostname, key_type, b64_key):
    """Compute expected SSHFP records for a given key line."""
    return derive_sshfp_from_host_keys([f"{hostname} {key_type} {b64_key}"])


class TestSSHFPCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_sshfp_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "sshfp.json"
        data = {
            "server": ["server IN SSHFP 1 2 abc123"],
            "desktop": ["desktop IN SSHFP 4 2 def456"],
        }
        save_sshfp_cache(cache_path, data)
        loaded = load_sshfp_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "sshfp.json"
        save_sshfp_cache(cache_path, {"host": ["record"]})
        assert cache_path.exists()


class TestEnrichHostsWithSSHFP:
    def test_enriches_matching_hosts(self):
        hosts = [_make_host("server", "10.1.10.1"), _make_host("desktop", "10.1.10.2")]
        sshfp_data = {"server": ["server IN SSHFP 1 2 abc123"]}

        enrich_hosts_with_sshfp(hosts, sshfp_data)

        assert hosts[0].sshfp_records == ["server IN SSHFP 1 2 abc123"]
        assert hosts[1].sshfp_records == []

    def test_no_sshfp_data(self):
        hosts = [_make_host("server", "10.1.10.1")]
        enrich_hosts_with_sshfp(hosts, {})
        assert hosts[0].sshfp_records == []

    def test_multiple_records_per_host(self):
        hosts = [_make_host("server", "10.1.10.1")]
        sshfp_data = {
            "server": [
                "server IN SSHFP 1 2 abc123",
                "server IN SSHFP 4 2 def456",
            ]
        }

        enrich_hosts_with_sshfp(hosts, sshfp_data)

        assert len(hosts[0].sshfp_records) == 2


class TestScanSSHFP:
    """Tests for scan_sshfp (legacy compatibility wrapper).

    scan_sshfp delegates to scan_ssh_host_keys internally, so we mock
    _keyscan_pubkeys (the new internal function) and verify the derived
    SSHFP records are returned.
    """

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_finds_sshfp(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = True
        mock_keyscan.return_value = [f"server ssh-rsa {_TEST_KEY_BLOB}"]
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert "server" in result
        expected = _expected_sshfp("server", "ssh-rsa", _TEST_KEY_BLOB)
        assert result["server"] == expected
        mock_keyscan.assert_called_once()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_skips_unreachable(self, mock_keyscan, tmp_path):
        reachability = {
            "server": HostReachability(hostname="server", active_ips=()),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert result == {}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_skips_no_ssh(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = False
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert result == {}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_skips_without_reachability(self, mock_keyscan, tmp_path):
        """Without reachability data, hosts are skipped."""
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp([host], cache_path, force=True, reachability=None)

        assert result == {}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_uses_cache_when_fresh(self, mock_keyscan, tmp_path):
        # scan_sshfp delegates to scan_ssh_host_keys which uses
        # ssh_host_keys.json — seed that cache file
        from gdoc2netcfg.supplements.sshfp import save_ssh_host_keys_cache

        cache_path = tmp_path / "ssh_host_keys.json"
        existing_keys = {"server": [f"server ssh-rsa {_TEST_KEY_BLOB}"]}
        save_ssh_host_keys_cache(cache_path, existing_keys)

        host = _make_host("server", "10.1.10.1")
        # scan_sshfp passes sshfp.json path, but internally constructs
        # ssh_host_keys.json in the same directory
        sshfp_cache_path = tmp_path / "sshfp.json"
        result = scan_sshfp([host], sshfp_cache_path, force=False, max_age=9999)

        expected = _expected_sshfp("server", "ssh-rsa", _TEST_KEY_BLOB)
        assert result == {"server": expected}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_saves_cache(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = True
        mock_keyscan.return_value = [f"server ssh-ed25519 {_TEST_ED25519_BLOB}"]
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        # scan_sshfp delegates to scan_ssh_host_keys which saves ssh_host_keys.json
        ssh_keys_cache = tmp_path / "ssh_host_keys.json"
        assert ssh_keys_cache.exists()
        import json
        loaded = json.loads(ssh_keys_cache.read_text())
        assert "server" in loaded

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_all_reachable_ips(self, mock_keyscan, mock_port, tmp_path):
        """SSH should be checked on all reachable IPs, not just the first."""
        # Port 22 open on both v4 and v6
        mock_port.return_value = True
        mock_keyscan.return_value = [f"server ssh-rsa {_TEST_KEY_BLOB}"]
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "2001:db8::1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        # check_port_open should be called for both IPs
        assert mock_port.call_count == 2
        port_ips = sorted(call.args[0] for call in mock_port.call_args_list)
        assert port_ips == ["10.1.10.1", "2001:db8::1"]

        # keyscan should be called for both IPs with SSH
        assert mock_keyscan.call_count == 2

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_only_ips_with_ssh(self, mock_keyscan, mock_port, tmp_path):
        """Only IPs with port 22 open should be keyscanned."""
        # Port 22 open only on v4
        mock_port.side_effect = lambda ip, port: ip == "10.1.10.1"
        mock_keyscan.return_value = [f"server ssh-rsa {_TEST_KEY_BLOB}"]
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "2001:db8::1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "sshfp.json"
        scan_sshfp(
            [host], cache_path, force=True, reachability=reachability,
        )

        # keyscan only called for the IP with SSH
        mock_keyscan.assert_called_once_with("10.1.10.1", "server")
