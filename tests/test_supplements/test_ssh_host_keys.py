"""Tests for the unified SSH host key scan and SSHFP derivation."""

import base64
import hashlib
from unittest.mock import patch

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.sshfp import (
    derive_sshfp_from_host_keys,
    enrich_hosts_with_ssh_host_keys,
    load_ssh_host_keys_cache,
    save_ssh_host_keys_cache,
    scan_ssh_host_keys,
)

# Fixed test key blobs for deterministic testing
_RSA_BLOB = b"test-rsa-key-blob-data"
_RSA_B64 = base64.b64encode(_RSA_BLOB).decode()
_ED25519_BLOB = b"test-ed25519-key-blob-data"
_ED25519_B64 = base64.b64encode(_ED25519_BLOB).decode()


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


class TestSSHHostKeysCache:
    def test_load_missing_returns_empty(self, tmp_path):
        result = load_ssh_host_keys_cache(tmp_path / "nonexistent.json")
        assert result == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        cache_path = tmp_path / "ssh_host_keys.json"
        data = {
            "server": [f"server ssh-rsa {_RSA_B64}"],
            "desktop": [f"desktop ssh-ed25519 {_ED25519_B64}"],
        }
        save_ssh_host_keys_cache(cache_path, data)
        loaded = load_ssh_host_keys_cache(cache_path)
        assert loaded == data

    def test_save_creates_parent_directory(self, tmp_path):
        cache_path = tmp_path / "subdir" / "ssh_host_keys.json"
        save_ssh_host_keys_cache(cache_path, {"host": ["record"]})
        assert cache_path.exists()


class TestDeriveSSHFP:
    def test_rsa_key_produces_sha1_and_sha256(self):
        keys = [f"server ssh-rsa {_RSA_B64}"]
        records = derive_sshfp_from_host_keys(keys)

        assert len(records) == 2

        # Verify SHA-1 record (algo=1 for ssh-rsa, fp_type=1)
        sha1_hex = hashlib.sha1(_RSA_BLOB).hexdigest()
        assert f"server IN SSHFP 1 1 {sha1_hex}" in records

        # Verify SHA-256 record (algo=1 for ssh-rsa, fp_type=2)
        sha256_hex = hashlib.sha256(_RSA_BLOB).hexdigest()
        assert f"server IN SSHFP 1 2 {sha256_hex}" in records

    def test_ed25519_key_uses_algo_4(self):
        keys = [f"myhost ssh-ed25519 {_ED25519_B64}"]
        records = derive_sshfp_from_host_keys(keys)

        assert len(records) == 2
        # ed25519 is algorithm 4
        assert all("SSHFP 4" in r for r in records)

    def test_ecdsa_key_uses_algo_3(self):
        blob = base64.b64encode(b"ecdsa-key-data").decode()
        keys = [f"host ecdsa-sha2-nistp256 {blob}"]
        records = derive_sshfp_from_host_keys(keys)

        assert len(records) == 2
        assert all("SSHFP 3" in r for r in records)

    def test_multiple_keys_sorted(self):
        keys = [
            f"server ssh-rsa {_RSA_B64}",
            f"server ssh-ed25519 {_ED25519_B64}",
        ]
        records = derive_sshfp_from_host_keys(keys)

        assert len(records) == 4  # 2 keys × 2 hash types
        # Records are sorted
        assert records == sorted(records)

    def test_malformed_key_raises(self):
        import pytest

        with pytest.raises(ValueError, match="Malformed SSH host key line"):
            derive_sshfp_from_host_keys(["just-hostname"])

    def test_unknown_key_type_raises(self):
        import pytest

        blob = base64.b64encode(b"data").decode()
        with pytest.raises(ValueError, match="Unknown SSH key type"):
            derive_sshfp_from_host_keys([f"host unknown-type {blob}"])

    def test_dss_key_uses_algo_2(self):
        blob = base64.b64encode(b"dss-key-data").decode()
        keys = [f"host ssh-dss {blob}"]
        records = derive_sshfp_from_host_keys(keys)

        assert len(records) == 2
        assert all("SSHFP 2" in r for r in records)


class TestEnrichHostsWithSSHHostKeys:
    def test_sets_both_fields(self):
        hosts = [_make_host("server", "10.1.10.1")]
        data = {"server": [f"server ssh-ed25519 {_ED25519_B64}"]}

        enrich_hosts_with_ssh_host_keys(hosts, data)

        assert hosts[0].ssh_host_keys == [f"server ssh-ed25519 {_ED25519_B64}"]
        assert len(hosts[0].sshfp_records) == 2
        assert all("SSHFP 4" in r for r in hosts[0].sshfp_records)

    def test_empty_data_clears_both(self):
        hosts = [_make_host("server", "10.1.10.1")]
        hosts[0].sshfp_records = ["old record"]
        hosts[0].ssh_host_keys = ["old key"]

        enrich_hosts_with_ssh_host_keys(hosts, {})

        assert hosts[0].ssh_host_keys == []
        assert hosts[0].sshfp_records == []

    def test_only_matching_hosts(self):
        hosts = [
            _make_host("server", "10.1.10.1"),
            _make_host("desktop", "10.1.10.2"),
        ]
        data = {"server": [f"server ssh-rsa {_RSA_B64}"]}

        enrich_hosts_with_ssh_host_keys(hosts, data)

        assert hosts[0].ssh_host_keys != []
        assert hosts[1].ssh_host_keys == []


class TestScanSSHHostKeys:
    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_finds_keys(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = True
        mock_keyscan.return_value = [f"server ssh-rsa {_RSA_B64}"]
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"
        result = scan_ssh_host_keys(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert "server" in result
        assert result["server"] == [f"server ssh-rsa {_RSA_B64}"]
        mock_keyscan.assert_called_once()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_skips_unreachable(self, mock_keyscan, tmp_path):
        reachability = {
            "server": HostReachability(hostname="server", active_ips=()),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"
        result = scan_ssh_host_keys(
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
        cache_path = tmp_path / "ssh_host_keys.json"
        result = scan_ssh_host_keys(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert result == {}
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_uses_cache_when_fresh(self, mock_keyscan, tmp_path):
        cache_path = tmp_path / "ssh_host_keys.json"
        existing = {"server": [f"server ssh-rsa {_RSA_B64}"]}
        save_ssh_host_keys_cache(cache_path, existing)

        host = _make_host("server", "10.1.10.1")
        result = scan_ssh_host_keys(
            [host], cache_path, force=False, max_age=9999,
        )

        assert result == existing
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_saves_cache(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = True
        mock_keyscan.return_value = [f"server ssh-ed25519 {_ED25519_B64}"]
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"
        scan_ssh_host_keys(
            [host], cache_path, force=True, reachability=reachability,
        )

        assert cache_path.exists()
        import json
        loaded = json.loads(cache_path.read_text())
        assert "server" in loaded
        assert loaded["server"] == [f"server ssh-ed25519 {_ED25519_B64}"]
