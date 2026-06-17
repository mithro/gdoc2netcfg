"""Tests for the password CLI command."""

import textwrap

import pytest

from gdoc2netcfg.cli.main import main
from gdoc2netcfg.storage.credentials_db import CredentialsDB


@pytest.fixture
def password_config(tmp_path):
    """Config with a credential-free CSV cache + a populated credentials.db."""
    cache_dir = tmp_path / ".cache"
    cache_dir.mkdir()

    # Credential-free CSV (Password/SNMP/IPMI columns stripped at fetch).
    (cache_dir / "network.csv").write_text(
        "Machine,MAC Address,IP,Interface\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
        "desktop,aa:bb:cc:dd:ee:02,10.1.10.2,\n"
        "server1,aa:bb:cc:dd:ee:03,10.1.10.5,\n"
    )

    # Credentials in the root-only store, keyed by hostname.
    # Derived hostnames for this minimal config are equal to machine names.
    with CredentialsDB(cache_dir / "credentials.db") as db:
        s = db.begin_scan("csv_credentials")
        db.save_credentials(s, {
            "switch1": {"Password": "sw1pass", "SNMP Community": "public"},
            "desktop": {"IPMI Username": "admin", "IPMI Password": "hunter2"},
            "server1": {"Password": "srv1pass", "SNMP Community": "community1"},
        })
        db.finish_scan(s, host_count=3, changed_count=5)

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
        30 = {{ name = "net", subdomain = "net" }}

        [network_subdomains]
        10 = "int"
        30 = "net"

        [generators]
        enabled = []
    """))
    return config


class TestPasswordByHostname:
    def test_lookup_by_machine_name(self, password_config, capsys):
        result = main(["-c", str(password_config), "password", "switch1"])
        assert result == 0
        captured = capsys.readouterr()
        assert "sw1pass" in captured.out
        assert "switch1" in captured.out

    def test_substring_no_longer_matches(self, password_config, capsys):
        """A partial name ('serv') must NOT resolve under exact matching."""
        result = main([
            "-c", str(password_config), "password", "serv",
        ])
        assert result == 1
        assert "no device found" in capsys.readouterr().err


class TestPasswordByIP:
    def test_lookup_by_ip(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "10.1.30.1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "sw1pass" in captured.out


class TestPasswordByMAC:
    def test_lookup_by_mac(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "aa:bb:cc:dd:ee:01",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "sw1pass" in captured.out


class TestPasswordQuietMode:
    def test_quiet_outputs_value_only(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "--quiet", "switch1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        # Quiet mode: only the password value, no headers
        assert captured.out.strip() == "sw1pass"
        assert "Host:" not in captured.out

    def test_quiet_ipmi_outputs_both_values(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--quiet", "--type", "ipmi", "desktop",
        ])
        assert result == 0
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert "admin" in lines
        assert "hunter2" in lines


class TestPasswordTypes:
    def test_snmp_type(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--type", "snmp", "switch1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "public" in captured.out
        assert "SNMP Community" in captured.out

    def test_ipmi_type(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--type", "ipmi", "desktop",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "admin" in captured.out
        assert "hunter2" in captured.out
        assert "IPMI Username" in captured.out
        assert "IPMI Password" in captured.out

    def test_field_flag(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password",
            "--field", "SNMP Community", "server1",
        ])
        assert result == 0
        captured = capsys.readouterr()
        assert "community1" in captured.out


class TestPasswordNoMatch:
    def test_no_match_returns_1(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "nonexistent",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "no device found" in captured.err

    def test_no_match_shows_suggestions(self, password_config, capsys):
        result = main([
            "-c", str(password_config), "password", "swtich1",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "Did you mean?" in captured.err


class TestPasswordMissingCredential:
    def test_host_found_but_no_password(self, password_config, capsys):
        # desktop has IPMI creds but no Password
        result = main([
            "-c", str(password_config), "password", "desktop",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "no 'password' credential found" in captured.err
        assert "Available fields:" in captured.err

    def test_host_found_but_no_snmp(self, password_config, capsys):
        # desktop has no SNMP Community
        result = main([
            "-c", str(password_config), "password",
            "--type", "snmp", "desktop",
        ])
        assert result == 1
        captured = capsys.readouterr()
        assert "no 'snmp' credential found" in captured.err


class TestPasswordMutuallyExclusive:
    def test_type_and_field_exclusive(self, password_config):
        """--type and --field are mutually exclusive (argparse enforces)."""
        with pytest.raises(SystemExit):
            main([
                "-c", str(password_config), "password",
                "--type", "snmp", "--field", "Password", "switch1",
            ])


class TestPasswordStoreErrors:
    def test_missing_store_fails_loud(self, tmp_path, capsys):
        # Credential-free cache but NO credentials.db.
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface\n"
            "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,\n"
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
            [generators]
            enabled = []
        """))
        result = main(["-c", str(config), "password", "switch1"])
        assert result == 1
        assert "fetch" in capsys.readouterr().err.lower()

    def test_field_for_noncredential_column_does_not_need_store(
        self, tmp_path, capsys,
    ):
        # No credentials.db; a non-credential --field still works sudo-free.
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        (cache_dir / "network.csv").write_text(
            "Machine,MAC Address,IP,Interface,Serial Number\n"
            "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,,SN123\n"
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
            [generators]
            enabled = []
        """))
        result = main([
            "-c", str(config), "password", "--field", "Serial Number", "switch1",
        ])
        assert result == 0
        assert "SN123" in capsys.readouterr().out
