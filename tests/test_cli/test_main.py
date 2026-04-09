"""Tests for the CLI entry point."""

import argparse
import json
import os
import textwrap
import time
from unittest.mock import patch

import pytest

from gdoc2netcfg.cli.main import _write_multi_file_output, main
from gdoc2netcfg.config import GeneratorConfig
from gdoc2netcfg.supplements.reachability import PingResult


@pytest.fixture
def test_config(tmp_path):
    """Create a minimal test config file."""
    config = tmp_path / "gdoc2netcfg.toml"
    config.write_text(textwrap.dedent("""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]

        [cache]
        directory = ".cache"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [vlans]
        10 = { name = "int", subdomain = "int" }

        [network_subdomains]
        10 = "int"

        [generators]
        enabled = ["dnsmasq_internal"]

        [generators.dnsmasq_internal]
        output = "dnsmasq.conf"
    """))
    return config


class TestMainArgParsing:
    def test_no_command_shows_help(self, capsys):
        result = main([])
        assert result == 0

    def test_info_command(self, test_config, capsys):
        result = main(["-c", str(test_config), "info"])
        assert result == 0
        captured = capsys.readouterr()
        assert "test" in captured.out
        assert "test.example.com" in captured.out

    def test_info_shows_vlans(self, test_config, capsys):
        main(["-c", str(test_config), "info"])
        captured = capsys.readouterr()
        assert "int" in captured.out

    def test_missing_config(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["-c", str(tmp_path / "missing.toml"), "info"])


class TestValidateCommand:
    def test_validate_with_no_data_exits(self, test_config, tmp_path):
        """Validate with no cached data should error."""
        with pytest.raises(SystemExit):
            main(["-c", str(test_config), "validate"])


class TestGenerateCommand:
    def test_generate_with_no_data_exits(self, test_config):
        """Generate with no cached data should error."""
        with pytest.raises(SystemExit):
            main(["-c", str(test_config), "generate"])

    def test_generate_with_cached_data(self, tmp_path, capsys):
        """Generate using cached CSV data."""
        # Create cache with sample data
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "desktop,aa:bb:cc:dd:ee:ff,10.1.10.1,\n"
        )

        # Create config pointing to cache
        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"

            [sheets]
            network = "https://example.com/not-used"

            [cache]
            directory = "{cache_dir}"

            [ipv6]
            prefixes = ["2001:db8:1:"]

            [vlans]
            10 = {{ name = "int", subdomain = "int" }}

            [network_subdomains]
            10 = "int"

            [generators]
            enabled = ["dnsmasq_internal"]

            [generators.dnsmasq_internal]
            output = ""
        """))

        result = main(["-c", str(config), "generate", "--stdout", "dnsmasq_internal"])
        assert result == 0
        captured = capsys.readouterr()
        assert "dhcp-host=" in captured.out
        assert "aa:bb:cc:dd:ee:ff" in captured.out

    def test_generate_unknown_generator(self, tmp_path, capsys):
        """Unknown generator name should warn but not crash."""
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "desktop,aa:bb:cc:dd:ee:ff,10.1.10.1,\n"
        )

        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"

            [sheets]
            network = "https://example.com/not-used"

            [cache]
            directory = "{cache_dir}"

            [ipv6]
            prefixes = []

            [vlans]

            [network_subdomains]

            [generators]
            enabled = []
        """))

        result = main(["-c", str(config), "generate", "--stdout", "nonexistent"])
        assert result == 0
        captured = capsys.readouterr()
        assert "unknown generator" in captured.err


class TestMultiFileOutput:
    def test_writes_multiple_files(self, tmp_path):
        output_dir = tmp_path / "nginx"
        gen_config = GeneratorConfig(name="nginx", output_dir=str(output_dir))
        args = argparse.Namespace(stdout=False)
        file_dict = {
            "sites-available/host1": "server { }",
            "snippets/acme.conf": "location /.well-known { }",
        }
        _write_multi_file_output("nginx", file_dict, gen_config, args)

        assert (output_dir / "sites-available" / "host1").exists()
        assert (output_dir / "snippets" / "acme.conf").exists()
        assert (output_dir / "sites-available" / "host1").read_text() == "server { }"

    def test_stdout_mode(self, capsys):
        gen_config = GeneratorConfig(name="nginx", output_dir="nginx")
        args = argparse.Namespace(stdout=True)
        file_dict = {
            "file1": "content1",
            "file2": "content2",
        }
        _write_multi_file_output("nginx", file_dict, gen_config, args)

        captured = capsys.readouterr()
        assert "# === nginx: file1 ===" in captured.out
        assert "content1" in captured.out
        assert "# === nginx: file2 ===" in captured.out

    def test_default_output_dir_is_name(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        gen_config = GeneratorConfig(name="nginx", output_dir="")
        args = argparse.Namespace(stdout=False)
        _write_multi_file_output("nginx", {"f.txt": "x"}, gen_config, args)
        assert (tmp_path / "nginx" / "f.txt").exists()

    def test_path_traversal_blocked(self, tmp_path, capsys):
        output_dir = tmp_path / "nginx"
        gen_config = GeneratorConfig(name="nginx", output_dir=str(output_dir))
        args = argparse.Namespace(stdout=False)
        file_dict = {
            "../../etc/passwd": "malicious content",
            "sites-available/legit": "good content",
        }
        _write_multi_file_output("nginx", file_dict, gen_config, args)

        # Legitimate file should be written
        assert (output_dir / "sites-available" / "legit").exists()
        # Traversal path should NOT be written
        assert not (tmp_path / "etc" / "passwd").exists()
        captured = capsys.readouterr()
        assert "path traversal" in captured.err


class TestDnsmasqExternalGenerator:
    def test_generate_dnsmasq_external_with_no_public_ip(self, tmp_path, capsys):
        """External generator with no public IP produces no-op output."""
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "desktop,aa:bb:cc:dd:ee:ff,10.1.10.1,\n"
        )

        config = tmp_path / "gdoc2netcfg.toml"
        config.write_text(textwrap.dedent(f"""\
            [site]
            name = "test"
            domain = "test.example.com"

            [sheets]
            network = "https://example.com/not-used"

            [cache]
            directory = "{cache_dir}"

            [ipv6]
            prefixes = []

            [vlans]
            10 = {{ name = "int", subdomain = "int" }}

            [network_subdomains]
            10 = "int"

            [generators]
            enabled = ["dnsmasq_external"]

            [generators.dnsmasq_external]
            output = ""
        """))

        result = main(["-c", str(config), "generate", "--stdout", "dnsmasq_external"])
        assert result == 0
        captured = capsys.readouterr()
        # With no public_ipv4, the external generator returns an empty dict,
        # so the CLI writes 0 files and produces no stdout output
        assert "No public_ipv4 configured" not in captured.out


def _make_config_with_csv(tmp_path):
    """Create a minimal config + cached CSV for reachability tests."""
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\n"
        "desktop,aa:bb:cc:dd:ee:ff,10.1.10.1,\n"
    )
    config = tmp_path / "gdoc2netcfg.toml"
    config.write_text(textwrap.dedent(f"""\
        [site]
        name = "test"
        domain = "test.example.com"

        [sheets]
        network = "https://example.com/not-used"

        [cache]
        directory = "{cache_dir}"

        [ipv6]
        prefixes = ["2001:db8:1:"]

        [vlans]
        10 = {{ name = "int", subdomain = "int" }}

        [network_subdomains]
        10 = "int"

        [generators]
        enabled = []
    """))
    return config, cache_dir


class TestReachabilityCache:
    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_reachability_creates_cache_file(self, mock_ping, tmp_path, capsys):
        """Running reachability should create .cache/reachability.json."""
        mock_ping.return_value = PingResult(10, 10, 0.5)
        config, cache_dir = _make_config_with_csv(tmp_path)

        result = main(["-c", str(config), "reachability"])

        assert result == 0
        cache_file = cache_dir / "reachability.json"
        assert cache_file.exists()
        data = json.loads(cache_file.read_text())
        assert data["version"] == 2
        assert "desktop" in data["hosts"]
        ifaces = data["hosts"]["desktop"]["interfaces"]
        # Single interface with IPv4 + IPv6 pings
        assert len(ifaces) == 1
        ips = [p["ip"] for p in ifaces[0]]
        assert "10.1.10.1" in ips
        assert "2001:db8:1:110::1" in ips

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_reachability_uses_cache_on_second_run(self, mock_ping, tmp_path, capsys):
        """Second run within 5 min should use cache, not re-ping."""
        mock_ping.return_value = PingResult(10, 10, 0.5)
        config, cache_dir = _make_config_with_csv(tmp_path)

        # First run — should ping
        main(["-c", str(config), "reachability"])
        first_call_count = mock_ping.call_count

        # Second run — should use cache
        main(["-c", str(config), "reachability"])
        captured = capsys.readouterr()

        assert mock_ping.call_count == first_call_count  # no new pings
        assert "Using cached reachability" in captured.err

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_reachability_force_bypasses_cache(self, mock_ping, tmp_path, capsys):
        """--force should re-ping even if cache is fresh."""
        mock_ping.return_value = PingResult(10, 10, 0.5)
        config, cache_dir = _make_config_with_csv(tmp_path)

        # First run — creates cache
        main(["-c", str(config), "reachability"])
        first_call_count = mock_ping.call_count

        # Second run with --force — should re-ping
        main(["-c", str(config), "reachability", "--force"])

        assert mock_ping.call_count > first_call_count

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_stale_cache_triggers_rescan(self, mock_ping, tmp_path, capsys):
        """Expired cache should trigger a fresh scan."""
        mock_ping.return_value = PingResult(10, 10, 0.5)
        config, cache_dir = _make_config_with_csv(tmp_path)

        # First run — creates cache
        main(["-c", str(config), "reachability"])
        first_call_count = mock_ping.call_count

        # Backdate the cache file and remove the DB (which has a fresh scan)
        cache_file = cache_dir / "reachability.json"
        old_time = time.time() - 600
        os.utime(cache_file, (old_time, old_time))
        db_file = cache_dir / "discovery.db"
        if db_file.exists():
            db_file.unlink()

        # Second run — cache is stale, should re-ping
        main(["-c", str(config), "reachability"])

        assert mock_ping.call_count > first_call_count

    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_cached_and_live_output_differ_by_one_line(self, mock_ping, tmp_path, capsys):
        """Cached and live stderr output should differ only in the header line."""
        mock_ping.return_value = PingResult(10, 10, 0.5)
        config, cache_dir = _make_config_with_csv(tmp_path)

        # Live run (--force)
        main(["-c", str(config), "reachability", "--force"])
        live_err = capsys.readouterr().err

        # Cached run (no --force, cache is fresh)
        main(["-c", str(config), "reachability"])
        cached_err = capsys.readouterr().err

        live_lines = live_err.strip().splitlines()
        cached_lines = cached_err.strip().splitlines()

        # Find the reachability header lines (skip any earlier warnings).
        live_header_idx = next(
            i for i, line in enumerate(live_lines)
            if line == "Checking host reachability..."
        )
        cached_header_idx = next(
            i for i, line in enumerate(cached_lines)
            if line.startswith("Using cached reachability (")
        )

        # Everything after the header line should be identical —
        # the per-host detail lines and the summary line.
        assert live_lines[live_header_idx + 1:] == cached_lines[cached_header_idx + 1:]
