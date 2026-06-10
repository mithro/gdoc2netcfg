"""Tests for the DiscoveryDB storage layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from gdoc2netcfg.storage.discovery_db import DiscoveryDB


@pytest.fixture()
def db(tmp_path: Path) -> DiscoveryDB:
    d = DiscoveryDB(tmp_path / "discovery.db")
    yield d
    d.close()


# -- Reachability ----------------------------------------------------------

class TestReachability:
    def _make_data(
        self,
        hostname: str = "server1",
        ips: list[tuple[str, int, int, float | None]] | None = None,
    ) -> dict:
        """Build reachability data in v2 dict format."""
        if ips is None:
            ips = [("10.1.10.1", 10, 10, 5.2)]
        pings = [
            {"ip": ip, "transmitted": tx, "received": rx, "rtt_avg_ms": rtt}
            for ip, tx, rx, rtt in ips
        ]
        return {hostname: {"interfaces": [pings]}}

    def test_save_and_load(self, db: DiscoveryDB):
        s = db.begin_scan("reachability")
        data = self._make_data()
        changed = db.save_reachability(s, data)
        db.finish_scan(s, host_count=1, changed_count=changed)

        assert changed == 1
        loaded = db.load_latest_reachability()
        assert loaded is not None
        assert "server1" in loaded
        pings = loaded["server1"]["interfaces"][0]
        assert len(pings) == 1
        assert pings[0]["ip"] == "10.1.10.1"
        assert pings[0]["transmitted"] == 10
        assert pings[0]["received"] == 10
        assert pings[0]["rtt_avg_ms"] == 5.2

    def test_load_returns_none_with_no_scans(self, db: DiscoveryDB):
        assert db.load_latest_reachability() is None

    def test_delta_ignores_rtt_change(self, db: DiscoveryDB):
        """Same status, different RTT -> no change."""
        s1 = db.begin_scan("reachability")
        data1 = self._make_data(ips=[("10.1.10.1", 10, 10, 5.2)])
        db.save_reachability(s1, data1)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("reachability")
        data2 = self._make_data(ips=[("10.1.10.1", 10, 10, 8.7)])
        changed = db.save_reachability(s2, data2)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_delta_ignores_packet_count_change(self, db: DiscoveryDB):
        """Same reachability, different packet counts -> no change."""
        s1 = db.begin_scan("reachability")
        data1 = self._make_data(ips=[("10.1.10.1", 10, 10, 5.0)])
        db.save_reachability(s1, data1)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("reachability")
        data2 = self._make_data(ips=[("10.1.10.1", 10, 9, 5.0)])
        changed = db.save_reachability(s2, data2)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        # 10 received vs 9 received: both > 0, so still "reachable"
        assert changed == 0

    def test_delta_detects_status_change(self, db: DiscoveryDB):
        """Host becomes unreachable -> change detected."""
        s1 = db.begin_scan("reachability")
        data1 = self._make_data(ips=[("10.1.10.1", 10, 10, 5.0)])
        db.save_reachability(s1, data1)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("reachability")
        data2 = self._make_data(ips=[("10.1.10.1", 10, 0, None)])
        changed = db.save_reachability(s2, data2)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_delta_detects_new_ip(self, db: DiscoveryDB):
        """New IP added to host -> change detected."""
        s1 = db.begin_scan("reachability")
        data1 = self._make_data(ips=[("10.1.10.1", 10, 10, 5.0)])
        db.save_reachability(s1, data1)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("reachability")
        data2 = self._make_data(ips=[
            ("10.1.10.1", 10, 10, 5.0),
            ("2001:db8::1", 10, 10, 6.0),
        ])
        changed = db.save_reachability(s2, data2)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_multiple_interfaces(self, db: DiscoveryDB):
        """Multi-interface host round-trips correctly."""
        data = {
            "server1": {
                "interfaces": [
                    [{"ip": "10.1.10.1", "transmitted": 10, "received": 10, "rtt_avg_ms": 5.0}],
                    [{"ip": "10.1.20.1", "transmitted": 10, "received": 0, "rtt_avg_ms": None}],
                ]
            }
        }
        s = db.begin_scan("reachability")
        db.save_reachability(s, data)
        db.finish_scan(s, host_count=1, changed_count=1)

        loaded = db.load_latest_reachability()
        assert len(loaded["server1"]["interfaces"]) == 2
        assert loaded["server1"]["interfaces"][0][0]["received"] == 10
        assert loaded["server1"]["interfaces"][1][0]["received"] == 0

    def test_multiple_hosts(self, db: DiscoveryDB):
        data = {
            "host_a": {"interfaces": [[
                {"ip": "10.1.10.1", "transmitted": 10, "received": 10, "rtt_avg_ms": 1.0},
            ]]},
            "host_b": {"interfaces": [[
                {"ip": "10.1.10.2", "transmitted": 10, "received": 0, "rtt_avg_ms": None},
            ]]},
        }
        s = db.begin_scan("reachability")
        changed = db.save_reachability(s, data)
        db.finish_scan(s, host_count=2, changed_count=changed)
        assert changed == 2

        loaded = db.load_latest_reachability()
        assert set(loaded.keys()) == {"host_a", "host_b"}


# -- SSH host keys ---------------------------------------------------------

class TestSSHHostKeys:
    def _make_data(
        self,
        hostname: str = "server1",
        keys: list[str] | None = None,
    ) -> dict[str, list[str]]:
        if keys is None:
            keys = [
                f"{hostname} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
                f"{hostname} ssh-rsa AAAAB3NzaC1yc2EAAAATest",
            ]
        return {hostname: keys}

    def test_save_and_load(self, db: DiscoveryDB):
        s = db.begin_scan("ssh_host_keys")
        data = self._make_data()
        changed = db.save_ssh_host_keys(s, data)
        db.finish_scan(s, host_count=1, changed_count=changed)

        assert changed == 1
        loaded = db.load_latest_ssh_host_keys()
        assert loaded is not None
        assert "server1" in loaded
        assert len(loaded["server1"]) == 2

    def test_load_returns_none_with_no_scans(self, db: DiscoveryDB):
        assert db.load_latest_ssh_host_keys() is None

    def test_key_line_reassembly(self, db: DiscoveryDB):
        """Keys are decomposed on save and reassembled on load."""
        original_keys = [
            "server1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1",
        ]
        s = db.begin_scan("ssh_host_keys")
        db.save_ssh_host_keys(s, {"server1": original_keys})
        db.finish_scan(s, host_count=1, changed_count=1)

        loaded = db.load_latest_ssh_host_keys()
        assert loaded["server1"] == original_keys

    def test_delta_no_change(self, db: DiscoveryDB):
        data = self._make_data()
        s1 = db.begin_scan("ssh_host_keys")
        db.save_ssh_host_keys(s1, data)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("ssh_host_keys")
        changed = db.save_ssh_host_keys(s2, data)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_delta_detects_new_key_type(self, db: DiscoveryDB):
        s1 = db.begin_scan("ssh_host_keys")
        db.save_ssh_host_keys(s1, {"h": ["h ssh-rsa AAAA"]})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("ssh_host_keys")
        changed = db.save_ssh_host_keys(
            s2, {"h": ["h ssh-rsa AAAA", "h ssh-ed25519 BBBB"]}
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_delta_detects_key_data_change(self, db: DiscoveryDB):
        s1 = db.begin_scan("ssh_host_keys")
        db.save_ssh_host_keys(s1, {"h": ["h ssh-ed25519 OLD"]})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("ssh_host_keys")
        changed = db.save_ssh_host_keys(s2, {"h": ["h ssh-ed25519 NEW"]})
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_delta_key_order_irrelevant(self, db: DiscoveryDB):
        """Same keys in different order -> no change."""
        keys1 = ["h ssh-rsa AAAA", "h ssh-ed25519 BBBB"]
        keys2 = ["h ssh-ed25519 BBBB", "h ssh-rsa AAAA"]

        s1 = db.begin_scan("ssh_host_keys")
        db.save_ssh_host_keys(s1, {"h": keys1})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("ssh_host_keys")
        changed = db.save_ssh_host_keys(s2, {"h": keys2})
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0


# -- SSL certs -------------------------------------------------------------

class TestSSLCerts:
    def _make_cert(
        self,
        issuer: str = "Let's Encrypt",
        self_signed: bool = False,
        valid: bool = True,
        expiry: str = "2025-12-31",
        sans: list[str] | None = None,
    ) -> dict:
        return {
            "issuer": issuer,
            "self_signed": self_signed,
            "valid": valid,
            "expiry": expiry,
            "sans": sans or ["server1.example.com"],
        }

    def test_save_and_load(self, db: DiscoveryDB):
        s = db.begin_scan("ssl_certs")
        data = {"server1": self._make_cert()}
        changed = db.save_ssl_certs(s, data)
        db.finish_scan(s, host_count=1, changed_count=changed)

        loaded = db.load_latest_ssl_certs()
        assert loaded is not None
        assert loaded["server1"]["issuer"] == "Let's Encrypt"
        assert loaded["server1"]["valid"] is True
        assert loaded["server1"]["self_signed"] is False
        assert loaded["server1"]["sans"] == ["server1.example.com"]

    def test_load_returns_none(self, db: DiscoveryDB):
        assert db.load_latest_ssl_certs() is None

    def test_delta_no_change(self, db: DiscoveryDB):
        cert = self._make_cert()
        s1 = db.begin_scan("ssl_certs")
        db.save_ssl_certs(s1, {"h": cert})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("ssl_certs")
        changed = db.save_ssl_certs(s2, {"h": cert})
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_delta_detects_expiry_change(self, db: DiscoveryDB):
        s1 = db.begin_scan("ssl_certs")
        db.save_ssl_certs(s1, {"h": self._make_cert(expiry="2025-06-01")})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("ssl_certs")
        changed = db.save_ssl_certs(
            s2, {"h": self._make_cert(expiry="2025-12-01")}
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_delta_detects_issuer_change(self, db: DiscoveryDB):
        s1 = db.begin_scan("ssl_certs")
        db.save_ssl_certs(s1, {"h": self._make_cert(issuer="LE")})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("ssl_certs")
        changed = db.save_ssl_certs(
            s2, {"h": self._make_cert(issuer="Comodo")}
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_bool_roundtrip(self, db: DiscoveryDB):
        """Booleans survive save/load (SQLite stores as 0/1)."""
        s = db.begin_scan("ssl_certs")
        db.save_ssl_certs(s, {"h": self._make_cert(self_signed=True)})
        db.finish_scan(s, host_count=1, changed_count=1)

        loaded = db.load_latest_ssl_certs()
        assert loaded["h"]["self_signed"] is True


# -- BMC firmware ----------------------------------------------------------

class TestBMCFirmware:
    def _make_bmc(
        self,
        product: str = "X11SPM-TF",
        fw_rev: str = "1.35.07",
        ipmi: str = "2.0",
        series: int | None = 11,
        snmp: bool = True,
    ) -> dict:
        return {
            "product_name": product,
            "firmware_revision": fw_rev,
            "ipmi_version": ipmi,
            "series": series,
            "snmp_capable": snmp,
        }

    def test_save_and_load(self, db: DiscoveryDB):
        s = db.begin_scan("bmc_firmware")
        data = {"bmc.server1": self._make_bmc()}
        changed = db.save_bmc_firmware(s, data)
        db.finish_scan(s, host_count=1, changed_count=changed)

        loaded = db.load_latest_bmc_firmware()
        assert loaded is not None
        assert loaded["bmc.server1"]["product_name"] == "X11SPM-TF"
        assert loaded["bmc.server1"]["series"] == 11

    def test_load_returns_none(self, db: DiscoveryDB):
        assert db.load_latest_bmc_firmware() is None

    def test_delta_no_change(self, db: DiscoveryDB):
        bmc = self._make_bmc()
        s1 = db.begin_scan("bmc_firmware")
        db.save_bmc_firmware(s1, {"h": bmc})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("bmc_firmware")
        changed = db.save_bmc_firmware(s2, {"h": bmc})
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_delta_detects_firmware_update(self, db: DiscoveryDB):
        s1 = db.begin_scan("bmc_firmware")
        db.save_bmc_firmware(s1, {"h": self._make_bmc(fw_rev="1.35")})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("bmc_firmware")
        changed = db.save_bmc_firmware(
            s2, {"h": self._make_bmc(fw_rev="1.36")}
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_nullable_series(self, db: DiscoveryDB):
        s = db.begin_scan("bmc_firmware")
        db.save_bmc_firmware(s, {"h": self._make_bmc(series=None)})
        db.finish_scan(s, host_count=1, changed_count=1)

        loaded = db.load_latest_bmc_firmware()
        assert loaded["h"]["series"] is None


# -- JSON-blob supplements ------------------------------------------------

class TestJSONBlob:
    """Tests for SNMP, bridge, NSDP, and tasmota (shared JSON-blob pattern)."""

    @pytest.mark.parametrize("save_fn,load_fn,scan_type", [
        ("save_snmp", "load_latest_snmp", "snmp"),
        ("save_bridge", "load_latest_bridge", "bridge"),
        ("save_nsdp", "load_latest_nsdp", "nsdp"),
        ("save_tasmota", "load_latest_tasmota", "tasmota"),
    ])
    def test_save_and_load(self, db: DiscoveryDB, save_fn, load_fn, scan_type):
        data = {"host1": {"key": "value", "nested": {"a": 1}}}
        s = db.begin_scan(scan_type)
        changed = getattr(db, save_fn)(s, data)
        db.finish_scan(s, host_count=1, changed_count=changed)

        assert changed == 1
        loaded = getattr(db, load_fn)()
        assert loaded is not None
        assert loaded["host1"] == {"key": "value", "nested": {"a": 1}}

    @pytest.mark.parametrize("save_fn,load_fn,scan_type", [
        ("save_snmp", "load_latest_snmp", "snmp"),
        ("save_bridge", "load_latest_bridge", "bridge"),
        ("save_nsdp", "load_latest_nsdp", "nsdp"),
        ("save_tasmota", "load_latest_tasmota", "tasmota"),
    ])
    def test_load_returns_none(self, db: DiscoveryDB, save_fn, load_fn, scan_type):
        assert getattr(db, load_fn)() is None

    @pytest.mark.parametrize("save_fn,scan_type", [
        ("save_snmp", "snmp"),
        ("save_bridge", "bridge"),
        ("save_nsdp", "nsdp"),
        ("save_tasmota", "tasmota"),
    ])
    def test_delta_no_change(self, db: DiscoveryDB, save_fn, scan_type):
        data = {"host1": {"key": "value"}}
        s1 = db.begin_scan(scan_type)
        getattr(db, save_fn)(s1, data)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan(scan_type)
        changed = getattr(db, save_fn)(s2, data)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    @pytest.mark.parametrize("save_fn,scan_type", [
        ("save_snmp", "snmp"),
        ("save_bridge", "bridge"),
        ("save_nsdp", "nsdp"),
        ("save_tasmota", "tasmota"),
    ])
    def test_delta_detects_value_change(self, db: DiscoveryDB, save_fn, scan_type):
        s1 = db.begin_scan(scan_type)
        getattr(db, save_fn)(s1, {"host1": {"key": "old"}})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan(scan_type)
        changed = getattr(db, save_fn)(s2, {"host1": {"key": "new"}})
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_json_key_order_irrelevant(self, db: DiscoveryDB):
        """Same data with different key order -> no change."""
        import collections

        # Use OrderedDict to guarantee different insertion order
        data1 = {"h": collections.OrderedDict([("a", 1), ("b", 2)])}
        data2 = {"h": collections.OrderedDict([("b", 2), ("a", 1)])}

        s1 = db.begin_scan("snmp")
        db.save_snmp(s1, data1)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("snmp")
        changed = db.save_snmp(s2, data2)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_tasmota_unknown_keys_preserved(self, db: DiscoveryDB):
        """Tasmota _unknown/{ip} keys are stored verbatim."""
        data = {
            "known-device": {"device_name": "plug1"},
            "_unknown/10.1.90.42": {"device_name": "mystery"},
        }
        s = db.begin_scan("tasmota")
        changed = db.save_tasmota(s, data)
        db.finish_scan(s, host_count=2, changed_count=changed)

        loaded = db.load_latest_tasmota()
        assert "_unknown/10.1.90.42" in loaded
        assert loaded["_unknown/10.1.90.42"]["device_name"] == "mystery"

    def test_multiple_hosts_partial_change(self, db: DiscoveryDB):
        """Only changed hosts get new rows."""
        s1 = db.begin_scan("snmp")
        db.save_snmp(s1, {
            "sw1": {"sysName": "switch1"},
            "sw2": {"sysName": "switch2"},
        })
        db.finish_scan(s1, host_count=2, changed_count=2)

        s2 = db.begin_scan("snmp")
        changed = db.save_snmp(s2, {
            "sw1": {"sysName": "switch1"},  # unchanged
            "sw2": {"sysName": "switch2-renamed"},  # changed
        })
        db.finish_scan(s2, host_count=2, changed_count=changed)
        assert changed == 1


# -- History ---------------------------------------------------------------

class TestHistory:
    def test_host_changes(self, db: DiscoveryDB):
        s1 = db.begin_scan("snmp")
        db.save_snmp(s1, {"sw1": {"version": "1.0"}})
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("snmp")
        db.save_snmp(s2, {"sw1": {"version": "2.0"}})
        db.finish_scan(s2, host_count=1, changed_count=1)

        changes = db.host_changes(
            "snmp_data", "sw1", scan_type="snmp"
        )
        assert len(changes) == 2
        assert changes[0][1]["version"] == "2.0"  # newest first
        assert changes[1][1]["version"] == "1.0"

    def test_host_changes_only_shows_changes(self, db: DiscoveryDB):
        """Scans with no change don't appear in history."""
        s1 = db.begin_scan("snmp")
        db.save_snmp(s1, {"sw1": {"v": "1.0"}})
        db.finish_scan(s1, host_count=1, changed_count=1)

        # No change
        s2 = db.begin_scan("snmp")
        db.save_snmp(s2, {"sw1": {"v": "1.0"}})
        db.finish_scan(s2, host_count=1, changed_count=0)

        # Actual change
        s3 = db.begin_scan("snmp")
        db.save_snmp(s3, {"sw1": {"v": "2.0"}})
        db.finish_scan(s3, host_count=1, changed_count=1)

        changes = db.host_changes(
            "snmp_data", "sw1", scan_type="snmp"
        )
        assert len(changes) == 2  # only s1 and s3

    def test_host_changes_since_filter(self, db: DiscoveryDB):
        s1 = db.begin_scan("snmp")
        db.save_snmp(s1, {"sw1": {"v": "1.0"}})
        db.finish_scan(s1, host_count=1, changed_count=1)

        changes = db.host_changes(
            "snmp_data", "sw1",
            scan_type="snmp",
            since="2099-01-01T00:00:00",
        )
        assert changes == []


# -- Reachability tombstones -------------------------------------------------

class TestReachabilityTombstones:
    def _scan(self, db: DiscoveryDB, data: dict) -> int:
        """Run one full scan cycle: save + tombstone + finish."""
        s = db.begin_scan("reachability")
        changed = db.save_reachability(s, data)
        changed += db.tombstone_missing_reachability(s, set(data))
        db.finish_scan(s, host_count=len(data), changed_count=changed)
        return s

    def _host(self, hostname: str, ip: str) -> dict:
        return {
            hostname: {
                "interfaces": [[{
                    "ip": ip, "transmitted": 10, "received": 10,
                    "rtt_avg_ms": 1.0,
                }]],
            },
        }

    def test_removed_host_is_tombstoned(self, db: DiscoveryDB):
        data = self._host("host-a", "10.1.10.1") | self._host("host-b", "10.1.10.2")
        self._scan(db, data)

        # host-b vanishes from the inventory.
        self._scan(db, self._host("host-a", "10.1.10.1"))

        latest = db.load_latest_reachability()
        assert "host-a" in latest
        assert "host-b" not in latest
        assert "host-b" not in db._latest_reachability_status()

    def test_history_is_retained(self, db: DiscoveryDB):
        """The tombstone is an INSERT-only delta — no rows are deleted."""
        data = self._host("host-b", "10.1.10.2")
        self._scan(db, data)
        self._scan(db, self._host("host-a", "10.1.10.1"))

        rows = db.connection.execute(
            "SELECT is_tombstone FROM reachability WHERE hostname = 'host-b' "
            "ORDER BY id"
        ).fetchall()
        # Original live row plus the tombstone row.
        assert [r[0] for r in rows] == [0, 1]

    def test_resurrection(self, db: DiscoveryDB):
        """A re-added host supersedes its tombstone automatically."""
        self._scan(db, self._host("host-a", "10.1.10.1")
                   | self._host("host-b", "10.1.10.2"))
        self._scan(db, self._host("host-a", "10.1.10.1"))
        assert "host-b" not in db.load_latest_reachability()

        self._scan(db, self._host("host-a", "10.1.10.1")
                   | self._host("host-b", "10.1.10.2"))
        latest = db.load_latest_reachability()
        assert latest["host-b"]["interfaces"][0][0]["ip"] == "10.1.10.2"

    def test_tombstone_is_idempotent(self, db: DiscoveryDB):
        """A second scan without the host tombstones nothing new."""
        self._scan(db, self._host("host-a", "10.1.10.1")
                   | self._host("host-b", "10.1.10.2"))
        self._scan(db, self._host("host-a", "10.1.10.1"))

        s = db.begin_scan("reachability")
        db.save_reachability(s, self._host("host-a", "10.1.10.1"))
        tombstoned = db.tombstone_missing_reachability(s, {"host-a"})
        db.finish_scan(s, host_count=1, changed_count=1)
        assert tombstoned == 0

    def test_empty_present_set_fails_loud(self, db: DiscoveryDB):
        self._scan(db, self._host("host-a", "10.1.10.1"))
        s = db.begin_scan("reachability")
        with pytest.raises(ValueError, match="refusing to tombstone"):
            db.tombstone_missing_reachability(s, set())

    def test_tombstone_counts_as_changed(self, db: DiscoveryDB):
        """The scan that tombstones reports it in changed_count."""
        self._scan(db, self._host("host-a", "10.1.10.1")
                   | self._host("host-b", "10.1.10.2"))

        s = db.begin_scan("reachability")
        changed = db.save_reachability(s, self._host("host-a", "10.1.10.1"))
        changed += db.tombstone_missing_reachability(s, {"host-a"})
        db.finish_scan(s, host_count=1, changed_count=changed)
        assert changed == 1  # host-a unchanged; host-b tombstoned


# -- Schema upgrade (v1 -> v2) ----------------------------------------------

class TestSchemaUpgrade:
    def _make_v1_db(self, path) -> None:
        """Create a current DB, then strip it back to schema v1."""
        d = DiscoveryDB(path)
        d.connection.execute("ALTER TABLE reachability DROP COLUMN is_tombstone")
        d.connection.execute(
            "UPDATE _meta SET value = '1' WHERE key = 'schema_version'"
        )
        d.connection.commit()
        d.close()

    def test_rw_open_upgrades_v1(self, tmp_path: Path):
        path = tmp_path / "v1.db"
        self._make_v1_db(path)

        d = DiscoveryDB(path)  # read-write open applies the upgrade
        cols = [r[1] for r in d.connection.execute(
            "PRAGMA table_info(reachability)"
        )]
        assert "is_tombstone" in cols
        version = d.connection.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert int(version) == DiscoveryDB.SCHEMA_VERSION
        d.close()

    def test_read_only_open_of_v1_fails_loud(self, tmp_path: Path):
        from gdoc2netcfg.storage.base import SchemaVersionError

        path = tmp_path / "v1.db"
        self._make_v1_db(path)

        with pytest.raises(SchemaVersionError, match="read-only open cannot"):
            DiscoveryDB(path, read_only=True)

    def test_newer_db_than_code_fails_loud(self, tmp_path: Path):
        from gdoc2netcfg.storage.base import SchemaVersionError

        path = tmp_path / "future.db"
        d = DiscoveryDB(path)
        d.connection.execute(
            "UPDATE _meta SET value = '99' WHERE key = 'schema_version'"
        )
        d.connection.commit()
        d.close()

        with pytest.raises(SchemaVersionError, match="newer than the code"):
            DiscoveryDB(path)
