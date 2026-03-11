"""Tests for the unified SSH host key scan and SSHFP derivation."""

import base64
import hashlib
from unittest.mock import patch

import pytest

from gdoc2netcfg.models.addressing import IPv4Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface
from gdoc2netcfg.supplements.reachability import HostReachability
from gdoc2netcfg.supplements.sshfp import (
    SSHKeyscanError,
    _keyscan_pubkeys,
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


class TestKeyscanPubkeys:
    """Tests for _keyscan_pubkeys error handling and output parsing."""

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_successful_scan(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "# 10.1.10.1:22 SSH-2.0-OpenSSH_9.2p1\n"
            f"10.1.10.1 ssh-rsa {_RSA_B64}\n"
            "# 10.1.10.1:22 SSH-2.0-OpenSSH_9.2p1\n"
            f"10.1.10.1 ssh-ed25519 {_ED25519_B64}\n"
        )
        mock_run.return_value.stderr = ""

        keys = _keyscan_pubkeys("10.1.10.1", "server")

        assert keys == [
            f"server ssh-ed25519 {_ED25519_B64}",
            f"server ssh-rsa {_RSA_B64}",
        ]

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_nonzero_exit_code_raises(self, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        with pytest.raises(SSHKeyscanError, match="exited with code 1"):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_timeout_raises(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="ssh-keyscan", timeout=10,
        )

        with pytest.raises(SSHKeyscanError, match="timed out"):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_success_but_no_keys_raises(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            "# 10.1.10.1:22 SSH-2.0-OpenSSH_9.2p1\n"
            "# 10.1.10.1:22 SSH-2.0-OpenSSH_9.2p1\n"
        )
        mock_run.return_value.stderr = ""

        with pytest.raises(SSHKeyscanError, match="no key lines"):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_malformed_output_raises(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "garbage-line-no-spaces\n"
        mock_run.return_value.stderr = ""

        with pytest.raises(SSHKeyscanError, match="Malformed"):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_hostname_substitution_uses_split_not_replace(self, mock_run):
        """Verify IP replacement uses field parsing, not str.replace."""
        mock_run.return_value.returncode = 0
        # Contrived: base64 blob that happens to contain "10.1.10.1"
        # str.replace would corrupt it, split/rejoin won't
        mock_run.return_value.stdout = (
            "10.1.10.1 ssh-rsa AAAA10.1.10.1BBBB\n"
        )
        mock_run.return_value.stderr = ""

        keys = _keyscan_pubkeys("10.1.10.1", "server")

        assert keys == ["server ssh-rsa AAAA10.1.10.1BBBB"]

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_two_field_line_raises(self, mock_run):
        """Output with only 'IP key-type' (missing base64) is malformed."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "10.1.10.1 ssh-rsa\n"
        mock_run.return_value.stderr = ""

        with pytest.raises(SSHKeyscanError, match="Malformed"):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_empty_stdout_exit_zero_raises(self, mock_run):
        """Exit 0 but completely empty stdout is an error."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        with pytest.raises(SSHKeyscanError, match="no key lines"):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_only_blank_lines_exit_zero_raises(self, mock_run):
        """Exit 0 with only blank/whitespace lines is an error."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "\n   \n\n"
        mock_run.return_value.stderr = ""

        with pytest.raises(SSHKeyscanError, match="no key lines"):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_stderr_included_in_error_message(self, mock_run):
        """stderr content is included in the error for diagnostics."""
        mock_run.return_value.returncode = 255
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "Connection refused"

        with pytest.raises(
            SSHKeyscanError, match="Connection refused",
        ):
            _keyscan_pubkeys("10.1.10.1", "server")

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_ipv6_address_parsing(self, mock_run):
        """IPv6 addresses are correctly replaced with hostname."""
        ipv6 = "2404:e80:a137:110a::1"
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            f"# {ipv6}:22 SSH-2.0-OpenSSH_9.2p1\n"
            f"{ipv6} ssh-ed25519 {_ED25519_B64}\n"
        )
        mock_run.return_value.stderr = ""

        keys = _keyscan_pubkeys(ipv6, "server")

        assert keys == [f"server ssh-ed25519 {_ED25519_B64}"]

    @patch("gdoc2netcfg.supplements.sshfp.subprocess.run")
    def test_nonzero_exit_with_partial_stdout_raises(self, mock_run):
        """Non-zero exit even with some stdout is an error."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = (
            f"10.1.10.1 ssh-rsa {_RSA_B64}\n"
        )
        mock_run.return_value.stderr = "partial failure"

        with pytest.raises(SSHKeyscanError, match="exited with code 1"):
            _keyscan_pubkeys("10.1.10.1", "server")


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
        with pytest.raises(ValueError, match="Malformed SSH host key line"):
            derive_sshfp_from_host_keys(["just-hostname"])

    def test_unknown_key_type_raises(self):
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

        assert hosts[0].ssh_host_keys == [
            f"server ssh-ed25519 {_ED25519_B64}",
        ]
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
        # reachability is required but won't be used — cache is fresh
        result = scan_ssh_host_keys(
            [host], cache_path, force=False, max_age=9999,
            reachability={},
        )

        assert result == existing
        mock_keyscan.assert_not_called()

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_saves_cache(self, mock_keyscan, mock_port, tmp_path):
        mock_port.return_value = True
        mock_keyscan.return_value = [
            f"server ssh-ed25519 {_ED25519_B64}",
        ]
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"
        scan_ssh_host_keys(
            [host], cache_path, force=True,
            reachability=reachability,
        )

        assert cache_path.exists()
        import json
        loaded = json.loads(cache_path.read_text())
        assert "server" in loaded
        assert loaded["server"] == [
            f"server ssh-ed25519 {_ED25519_B64}",
        ]

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_raises_on_keyscan_failure(
        self, mock_keyscan, mock_port, tmp_path,
    ):
        """Port 22 is open but ssh-keyscan fails → error, not silent skip."""
        mock_port.return_value = True
        mock_keyscan.side_effect = SSHKeyscanError(
            "ssh-keyscan 10.1.10.1 exited with code 1",
        )
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"

        with pytest.raises(SSHKeyscanError, match="1 SSH host key scan"):
            scan_ssh_host_keys(
                [host], cache_path, force=True,
                reachability=reachability,
            )

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_detects_inconsistent_keys_across_ips(
        self, mock_keyscan, mock_port, tmp_path,
    ):
        """Different keys from different IPs → error."""
        mock_port.return_value = True
        # Return different keys depending on which IP is scanned
        different_rsa_b64 = base64.b64encode(b"DIFFERENT-key").decode()
        mock_keyscan.side_effect = [
            [f"server ssh-rsa {_RSA_B64}"],
            [f"server ssh-rsa {different_rsa_b64}"],
        ]
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "10.1.20.1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"

        with pytest.raises(SSHKeyscanError, match="different SSH keys"):
            scan_ssh_host_keys(
                [host], cache_path, force=True,
                reachability=reachability,
            )

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_consistent_keys_across_ips(
        self, mock_keyscan, mock_port, tmp_path,
    ):
        """Same keys from all IPs → success."""
        mock_port.return_value = True
        same_keys = [
            f"server ssh-ed25519 {_ED25519_B64}",
            f"server ssh-rsa {_RSA_B64}",
        ]
        mock_keyscan.return_value = same_keys
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "10.1.20.1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"
        result = scan_ssh_host_keys(
            [host], cache_path, force=True,
            reachability=reachability,
        )

        assert "server" in result
        assert result["server"] == same_keys
        assert mock_keyscan.call_count == 2

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_collects_errors_from_multiple_hosts(
        self, mock_keyscan, mock_port, tmp_path,
    ):
        """Errors from multiple hosts are collected and reported together."""
        mock_port.return_value = True
        mock_keyscan.side_effect = SSHKeyscanError("connection refused")
        reachability = {
            "alpha": HostReachability(
                hostname="alpha", active_ips=("10.1.10.1",),
            ),
            "beta": HostReachability(
                hostname="beta", active_ips=("10.1.10.2",),
            ),
        }
        hosts = [
            _make_host("alpha", "10.1.10.1"),
            _make_host("beta", "10.1.10.2"),
        ]
        cache_path = tmp_path / "ssh_host_keys.json"

        with pytest.raises(SSHKeyscanError, match="2 SSH host key scan"):
            scan_ssh_host_keys(
                hosts, cache_path, force=True,
                reachability=reachability,
            )

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_partial_ip_failure_is_error(
        self, mock_keyscan, mock_port, tmp_path,
    ):
        """One IP succeeds but another fails → error, not partial result."""
        mock_port.return_value = True
        mock_keyscan.side_effect = [
            [f"server ssh-rsa {_RSA_B64}"],
            SSHKeyscanError("ssh-keyscan 10.1.20.1 timed out"),
        ]
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "10.1.20.1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"

        with pytest.raises(SSHKeyscanError, match="1 SSH host key scan"):
            scan_ssh_host_keys(
                [host], cache_path, force=True,
                reachability=reachability,
            )

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_subset_keys_across_ips_is_inconsistent(
        self, mock_keyscan, mock_port, tmp_path,
    ):
        """One IP returns a subset of another's keys → inconsistency error."""
        mock_port.return_value = True
        mock_keyscan.side_effect = [
            [
                f"server ssh-ed25519 {_ED25519_B64}",
                f"server ssh-rsa {_RSA_B64}",
            ],
            [f"server ssh-ed25519 {_ED25519_B64}"],
        ]
        reachability = {
            "server": HostReachability(
                hostname="server",
                active_ips=("10.1.10.1", "10.1.20.1"),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"

        with pytest.raises(SSHKeyscanError, match="different SSH keys"):
            scan_ssh_host_keys(
                [host], cache_path, force=True,
                reachability=reachability,
            )

    @patch("gdoc2netcfg.supplements.sshfp.check_port_open")
    @patch("gdoc2netcfg.supplements.sshfp._keyscan_pubkeys")
    def test_scan_does_not_save_cache_on_error(
        self, mock_keyscan, mock_port, tmp_path,
    ):
        """Cache is not written when scan has errors."""
        mock_port.return_value = True
        mock_keyscan.side_effect = SSHKeyscanError("failure")
        reachability = {
            "server": HostReachability(
                hostname="server", active_ips=("10.1.10.1",),
            ),
        }
        host = _make_host("server", "10.1.10.1")
        cache_path = tmp_path / "ssh_host_keys.json"

        with pytest.raises(SSHKeyscanError):
            scan_ssh_host_keys(
                [host], cache_path, force=True,
                reachability=reachability,
            )

        assert not cache_path.exists()
