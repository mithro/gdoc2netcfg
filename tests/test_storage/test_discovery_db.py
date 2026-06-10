"""Tests for the DiscoveryDB storage layer."""

from __future__ import annotations

import sqlite3
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

# -- Structured supplements (SNMP, bridge, NSDP, tasmota) --------------------
#
# Realistic minimal documents matching the live scanners' output shapes —
# the strict per-supplement validation rejects anything else.

def _snmp_doc(sys_name: str = "printer1") -> dict:
    return {
        "snmp_version": "v2c",
        "system_info": {
            "sysContact": "",
            "sysDescr": "Brother NC-9200w",
            "sysLocation": "",
            "sysName": sys_name,
            "sysObjectID": "1.3.6.1.4.1.2435.2.3.9.1",
            "sysUpTime": "371319035",
        },
        "interfaces": [
            {"1.3.6.1.2.1.2.2.1.1": "1", "1.3.6.1.2.1.2.2.1.2": "eth0"},
            {"1.3.6.1.2.1.2.2.1.1": "2", "1.3.6.1.2.1.2.2.1.2": "wlan0"},
        ],
        "ip_addresses": [{"1.3.6.1.2.1.4.20.1.1": "10.1.10.5"}],
        "raw": {"1.3.6.1.2.1.1.5.0": sys_name},
    }


def _bridge_doc(port_name: str = "2/0/49") -> dict:
    return {
        "mac_table": [["00:0A:FA:24:28:25", 1, 101, port_name]],
        "vlan_names": [[1, "default"], [90, "iot"]],
        "port_pvids": [[1, 1]],
        "port_names": [[1, "Port 1"]],
        "port_status": [[1, 1, 1000]],
        "lldp_neighbors": [[101, "sw-other", "gi27", "\xc8\x00q"]],
        "vlan_egress_ports": [[1, "ff00"]],
        "vlan_untagged_ports": [[1, "ff00"]],
        "poe_status": [],
        "port_statistics": [[1, 1000, 2000, 0]],
    }


def _nsdp_doc_full() -> dict:
    return {
        "model": "GS110EMX",
        "mac": "AA:BB:CC:DD:EE:01",
        "hostname": "sw-iot",
        "ip": "10.1.10.2",
        "netmask": "255.255.0.0",
        "gateway": "10.1.10.1",
        "firmware_version": "1.0.1.4",
        "dhcp_enabled": False,
        "port_count": 10,
        "serial_number": "X1A",
        "vlan_engine": 4,
        "qos_engine": 1,
        "port_mirroring_dest": 0,
        "igmp_snooping_enabled": True,
        "broadcast_filtering": False,
        "port_status": [[1, 5], [2, 0]],
        "port_pvids": [[1, 1], [2, 90]],
        "port_statistics": [[1, 100, 200, 0]],
        "vlan_members": [[1, [1, 2], [2]], [99, [], []]],
    }


def _tasmota_doc(name: str = "plug1", module: object = 43) -> dict:
    return {
        "device_name": name,
        "friendly_name": name,
        "hostname": f"tasmota-{name}",
        "firmware_version": "13.2.0",
        "mqtt_host": "mqtt.example",
        "mqtt_port": 1883,
        "mqtt_topic": name,
        "mqtt_client": f"DVES_{name}",
        "mqtt_user": "tasmota",
        "mac": "AA:BB:CC:00:11:22",
        "ip": "10.1.90.10",
        "wifi_ssid": "iot",
        "wifi_rssi": 80,
        "wifi_signal": -55,
        "uptime": "1T00:00:00",
        "module": module,
    }


class TestStructuredSupplements:
    """Shared per-entity delta behaviour across snmp/bridge/nsdp/tasmota."""

    CASES = [
        ("save_snmp", "load_latest_snmp", "snmp", _snmp_doc),
        ("save_bridge", "load_latest_bridge", "bridge", _bridge_doc),
        ("save_nsdp", "load_latest_nsdp", "nsdp", _nsdp_doc_full),
        ("save_tasmota", "load_latest_tasmota", "tasmota", _tasmota_doc),
    ]

    @pytest.mark.parametrize("save_fn,load_fn,scan_type,make_doc", CASES)
    def test_roundtrip_is_exact(
        self, db: DiscoveryDB, save_fn, load_fn, scan_type, make_doc,
    ):
        data = {"host1": make_doc()}
        s = db.begin_scan(scan_type)
        changed = getattr(db, save_fn)(s, data)
        db.finish_scan(s, host_count=1, changed_count=changed)

        assert changed == 1
        assert getattr(db, load_fn)() == data

    @pytest.mark.parametrize("save_fn,load_fn,scan_type,make_doc", CASES)
    def test_load_returns_none(
        self, db: DiscoveryDB, save_fn, load_fn, scan_type, make_doc,
    ):
        assert getattr(db, load_fn)() is None

    @pytest.mark.parametrize("save_fn,load_fn,scan_type,make_doc", CASES)
    def test_delta_no_change_writes_no_rows(
        self, db: DiscoveryDB, save_fn, load_fn, scan_type, make_doc,
    ):
        data = {"host1": make_doc()}
        s1 = db.begin_scan(scan_type)
        getattr(db, save_fn)(s1, data)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan(scan_type)
        changed = getattr(db, save_fn)(s2, data)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    @pytest.mark.parametrize("save_fn,scan_type,make_doc,mutate", [
        ("save_snmp", "snmp", _snmp_doc,
         lambda d: d["system_info"].__setitem__("sysName", "renamed")),
        ("save_bridge", "bridge", _bridge_doc,
         lambda d: d["mac_table"].append(["AA:00:00:00:00:01", 1, 5, "1"])),
        ("save_nsdp", "nsdp", _nsdp_doc_full,
         lambda d: d.__setitem__("firmware_version", "2.0.0")),
        ("save_tasmota", "tasmota", _tasmota_doc,
         lambda d: d.__setitem__("firmware_version", "14.0.0")),
    ])
    def test_delta_detects_value_change(
        self, db: DiscoveryDB, save_fn, scan_type, make_doc, mutate,
    ):
        s1 = db.begin_scan(scan_type)
        getattr(db, save_fn)(s1, {"host1": make_doc()})
        db.finish_scan(s1, host_count=1, changed_count=1)

        doc = make_doc()
        mutate(doc)
        s2 = db.begin_scan(scan_type)
        changed = getattr(db, save_fn)(s2, {"host1": doc})
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    @pytest.mark.parametrize("save_fn,scan_type,make_doc", [
        (s, t, m) for s, _l, t, m in CASES
    ])
    def test_unexpected_shape_fails_loud(
        self, db: DiscoveryDB, save_fn, scan_type, make_doc,
    ):
        doc = make_doc()
        doc["surprise_field"] = 1
        s = db.begin_scan(scan_type)
        with pytest.raises(ValueError, match="unexpected keys"):
            getattr(db, save_fn)(s, {"host1": doc})

    def test_only_changed_hosts_get_rows(self, db: DiscoveryDB):
        s1 = db.begin_scan("snmp")
        db.save_snmp(s1, {"sw1": _snmp_doc("sw1"), "sw2": _snmp_doc("sw2")})
        db.finish_scan(s1, host_count=2, changed_count=2)

        s2 = db.begin_scan("snmp")
        changed = db.save_snmp(s2, {
            "sw1": _snmp_doc("sw1"),          # unchanged
            "sw2": _snmp_doc("sw2-renamed"),  # changed
        })
        db.finish_scan(s2, host_count=2, changed_count=changed)
        assert changed == 1
        # sw1's rows still come from scan 1, sw2's from scan 2.
        rows = dict(db.connection.execute(
            "SELECT hostname, scan_id FROM snmp_hosts "
            "WHERE id IN (SELECT MAX(id) FROM snmp_hosts GROUP BY hostname)"
        ).fetchall())
        assert rows == {"sw1": s1, "sw2": s2}

    def test_tuples_from_live_scans_load_as_lists(self, db: DiscoveryDB):
        """Live scanners produce tuples; loads return lists (as the JSON
        round trip always did), and the delta comparison treats them as
        equal."""
        doc = _bridge_doc()
        doc["mac_table"] = [("00:0A:FA:24:28:25", 1, 101, "2/0/49")]
        s1 = db.begin_scan("bridge")
        db.save_bridge(s1, {"sw1": doc})
        db.finish_scan(s1, host_count=1, changed_count=1)

        assert db.load_latest_bridge()["sw1"] == _bridge_doc()

        s2 = db.begin_scan("bridge")
        changed = db.save_bridge(s2, {"sw1": doc})
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_history_rows_accumulate(self, db: DiscoveryDB):
        """Every change is a new row-set; old scans' rows remain."""
        s1 = db.begin_scan("snmp")
        db.save_snmp(s1, {"sw1": _snmp_doc("v1")})
        db.finish_scan(s1, host_count=1, changed_count=1)
        s2 = db.begin_scan("snmp")
        db.save_snmp(s2, {"sw1": _snmp_doc("v2")})
        db.finish_scan(s2, host_count=1, changed_count=1)

        names = [r[0] for r in db.connection.execute(
            "SELECT sys_name FROM snmp_hosts WHERE hostname = 'sw1' "
            "ORDER BY id"
        )]
        assert names == ["v1", "v2"]


class TestBridgeShapes:
    def test_document_without_port_statistics_roundtrips(self, db: DiscoveryDB):
        """Older scanner generations didn't collect port_statistics —
        the key must stay absent, not be fabricated as []."""
        doc = _bridge_doc()
        del doc["port_statistics"]
        s = db.begin_scan("bridge")
        changed = db.save_bridge(s, {"sw-old": doc})
        db.finish_scan(s, host_count=1, changed_count=changed)

        loaded = db.load_latest_bridge()
        assert loaded == {"sw-old": doc}
        assert "port_statistics" not in loaded["sw-old"]

    def test_empty_port_statistics_stays_present(self, db: DiscoveryDB):
        doc = _bridge_doc()
        doc["port_statistics"] = []
        s = db.begin_scan("bridge")
        db.save_bridge(s, {"sw1": doc})
        db.finish_scan(s, host_count=1, changed_count=1)
        assert db.load_latest_bridge()["sw1"]["port_statistics"] == []


class TestNSDPShapes:
    def _save(self, db: DiscoveryDB, data: dict) -> int:
        s = db.begin_scan("nsdp")
        changed = db.save_nsdp(s, data)
        db.finish_scan(s, host_count=len(data), changed_count=changed)
        return changed

    def test_minimal_document_roundtrip(self, db: DiscoveryDB):
        """Older switches report only model+mac plus a few fields —
        absent keys stay absent (not fabricated as None)."""
        doc = {"model": "GS108E", "mac": "AA:BB:CC:DD:EE:02"}
        self._save(db, {"sw-min": doc})
        assert db.load_latest_nsdp() == {"sw-min": doc}

    def test_memberless_vlan_survives(self, db: DiscoveryDB):
        doc = {
            "model": "GS110EMX", "mac": "AA:BB:CC:DD:EE:01",
            "vlan_members": [[99, [], []]],
        }
        self._save(db, {"sw1": doc})
        assert db.load_latest_nsdp()["sw1"]["vlan_members"] == [[99, [], []]]

    def test_tagged_not_subset_fails_loud(self, db: DiscoveryDB):
        doc = {
            "model": "GS110EMX", "mac": "AA:BB:CC:DD:EE:01",
            "vlan_members": [[1, [1], [2]]],
        }
        s = db.begin_scan("nsdp")
        with pytest.raises(ValueError, match="not a subset"):
            db.save_nsdp(s, {"sw1": doc})


class TestTasmotaShapes:
    def test_unknown_keys_preserved(self, db: DiscoveryDB):
        data = {
            "known-device": _tasmota_doc("plug1"),
            "_unknown/10.1.90.42": _tasmota_doc("mystery"),
        }
        s = db.begin_scan("tasmota")
        changed = db.save_tasmota(s, data)
        db.finish_scan(s, host_count=2, changed_count=changed)
        assert db.load_latest_tasmota() == data

    def test_module_type_roundtrip(self, db: DiscoveryDB):
        """module is int from live devices but '' from the builder's
        default — both types round-trip exactly."""
        data = {
            "plug-int": _tasmota_doc("a", module=43),
            "plug-str": _tasmota_doc("b", module=""),
        }
        s = db.begin_scan("tasmota")
        changed = db.save_tasmota(s, data)
        db.finish_scan(s, host_count=2, changed_count=changed)
        loaded = db.load_latest_tasmota()
        assert loaded["plug-int"]["module"] == 43
        assert loaded["plug-str"]["module"] == ""


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


# -- Zigbee ------------------------------------------------------------------

def _zb_device(site: str, ieee: str, **overrides) -> dict:
    d = {
        "site": site,
        "ieee_address": ieee,
        "friendly_name": "kitchen_temp",
        "object_id": "kitchen_temp",
        "device_type": "EndDevice",
        "model_id": "WSDCGQ12LM",
        "manufacturer": "Xiaomi",
        "model": "Aqara temperature sensor",
        "power_source": "Battery",
        "software_build_id": "100",
        "date_code": "2023-10-15",
        "last_seen": 1000,
        "link_quality": 80,
        "availability": "online",
        "network_address": 1234,
    }
    d.update(overrides)
    return d


def _zb_bridge(site: str, **overrides) -> dict:
    b = {
        "site": site,
        "z2m_version": "1.38.0",
        "coordinator_ieee": "0x00aa",
        "coordinator_type": "ConBee II",
        "channel": 15,
        "pan_id": "0x1a62",
    }
    b.update(overrides)
    return b


def _zb_site_doc(site: str, *devices: dict, bridge: dict | None = None) -> dict:
    return {
        "bridge": bridge if bridge is not None else _zb_bridge(site),
        "devices": {d["ieee_address"]: d for d in devices},
    }


class TestZigbee:
    """Per-device deltas: only updated devices get new rows; bridge
    info and tombstones are tracked per site."""

    def _save(self, db: DiscoveryDB, data: dict) -> int:
        s = db.begin_scan("zigbee")
        changed = db.save_zigbee(s, data)
        db.finish_scan(s, host_count=len(data), changed_count=changed)
        return changed

    def _device_rows(self, db: DiscoveryDB, site: str) -> int:
        return db.connection.execute(
            "SELECT COUNT(*) FROM zigbee_devices WHERE site = ?", (site,),
        ).fetchone()[0]

    def test_save_and_load(self, db: DiscoveryDB):
        data = {
            "welland": _zb_site_doc("welland", _zb_device("welland", "0x01")),
            "monarto": _zb_site_doc("monarto", _zb_device("monarto", "0x02")),
        }
        changed = self._save(db, data)
        assert changed == 4  # 2 site rows + 2 device rows
        assert db.load_latest_zigbee() == data

    def test_load_returns_none_with_no_scans(self, db: DiscoveryDB):
        assert db.load_latest_zigbee() is None

    def test_delta_ignores_volatile_device_fields(self, db: DiscoveryDB):
        """last_seen / link_quality churn alone never inserts a new row."""
        self._save(db, {
            "welland": _zb_site_doc("welland", _zb_device("welland", "0x01")),
        })
        changed = self._save(db, {
            "welland": _zb_site_doc(
                "welland",
                _zb_device("welland", "0x01", last_seen=2000, link_quality=60),
            ),
        })
        assert changed == 0

    def test_only_the_changed_device_gets_a_row(self, db: DiscoveryDB):
        """One device's change must not rewrite its site's other
        devices, the bridge row, or the other site."""
        self._save(db, {
            "welland": _zb_site_doc(
                "welland",
                _zb_device("welland", "0x01"),
                _zb_device("welland", "0x02"),
            ),
            "monarto": _zb_site_doc("monarto", _zb_device("monarto", "0x99")),
        })
        changed = self._save(db, {
            "welland": _zb_site_doc(
                "welland",
                _zb_device("welland", "0x01", availability="offline"),
                _zb_device("welland", "0x02"),
            ),
            "monarto": _zb_site_doc("monarto", _zb_device("monarto", "0x99")),
        })
        assert changed == 1
        assert self._device_rows(db, "welland") == 3  # 2 initial + 1 update
        assert self._device_rows(db, "monarto") == 1
        sites_rows = db.connection.execute(
            "SELECT COUNT(*) FROM zigbee_sites"
        ).fetchone()[0]
        assert sites_rows == 2  # one per site, from the first save only
        loaded = db.load_latest_zigbee()
        assert loaded["welland"]["devices"]["0x01"]["availability"] == "offline"
        assert loaded["welland"]["devices"]["0x02"]["availability"] == "online"

    def test_bridge_change_writes_only_a_site_row(self, db: DiscoveryDB):
        self._save(db, {
            "welland": _zb_site_doc("welland", _zb_device("welland", "0x01")),
        })
        changed = self._save(db, {
            "welland": _zb_site_doc(
                "welland", _zb_device("welland", "0x01"),
                bridge=_zb_bridge("welland", z2m_version="2.0.0"),
            ),
        })
        assert changed == 1
        assert self._device_rows(db, "welland") == 1  # untouched
        loaded = db.load_latest_zigbee()
        assert loaded["welland"]["bridge"]["z2m_version"] == "2.0.0"

    def test_volatile_fields_stored_on_real_change(self, db: DiscoveryDB):
        """When a row IS inserted, it carries the latest volatile values."""
        self._save(db, {
            "welland": _zb_site_doc("welland", _zb_device("welland", "0x01")),
        })
        self._save(db, {
            "welland": _zb_site_doc(
                "welland",
                _zb_device("welland", "0x01", availability="offline",
                           last_seen=2000),
            ),
        })
        loaded = db.load_latest_zigbee()
        assert loaded["welland"]["devices"]["0x01"]["last_seen"] == 2000

    def test_removed_device_is_tombstoned(self, db: DiscoveryDB):
        self._save(db, {
            "welland": _zb_site_doc(
                "welland",
                _zb_device("welland", "0x01"),
                _zb_device("welland", "0x02"),
            ),
        })
        changed = self._save(db, {
            "welland": _zb_site_doc("welland", _zb_device("welland", "0x01")),
        })
        assert changed == 1  # the device tombstone
        loaded = db.load_latest_zigbee()
        assert set(loaded["welland"]["devices"]) == {"0x01"}
        # History retained: initial row + tombstone row.
        rows = db.connection.execute(
            "SELECT is_tombstone FROM zigbee_devices "
            "WHERE site = 'welland' AND ieee_address = '0x02' ORDER BY id"
        ).fetchall()
        assert [r[0] for r in rows] == [0, 1]

    def test_device_resurrection(self, db: DiscoveryDB):
        device = _zb_device("welland", "0x02")
        self._save(db, {
            "welland": _zb_site_doc(
                "welland", _zb_device("welland", "0x01"), device,
            ),
        })
        self._save(db, {
            "welland": _zb_site_doc("welland", _zb_device("welland", "0x01")),
        })
        changed = self._save(db, {
            "welland": _zb_site_doc(
                "welland", _zb_device("welland", "0x01"), device,
            ),
        })
        assert changed == 1  # the resurrected device
        assert set(db.load_latest_zigbee()["welland"]["devices"]) == {
            "0x01", "0x02",
        }

    def test_removed_site_is_tombstoned_with_its_devices(self, db: DiscoveryDB):
        welland = _zb_site_doc("welland", _zb_device("welland", "0x01"))
        self._save(db, {
            "welland": welland,
            "monarto": _zb_site_doc("monarto", _zb_device("monarto", "0x02")),
        })
        changed = self._save(db, {"welland": welland})
        assert changed == 2  # site tombstone + its one device tombstone
        assert set(db.load_latest_zigbee()) == {"welland"}

    def test_site_tombstone_is_idempotent(self, db: DiscoveryDB):
        welland = _zb_site_doc("welland", _zb_device("welland", "0x01"))
        self._save(db, {
            "welland": welland,
            "monarto": _zb_site_doc("monarto", _zb_device("monarto", "0x02")),
        })
        self._save(db, {"welland": welland})
        changed = self._save(db, {"welland": welland})
        assert changed == 0

    def test_site_resurrection(self, db: DiscoveryDB):
        welland = _zb_site_doc("welland", _zb_device("welland", "0x01"))
        monarto = _zb_site_doc("monarto", _zb_device("monarto", "0x02"))
        self._save(db, {"welland": welland, "monarto": monarto})
        self._save(db, {"welland": welland})
        changed = self._save(db, {"welland": welland, "monarto": monarto})
        assert changed == 2  # site row + its device, re-inserted
        assert set(db.load_latest_zigbee()) == {"welland", "monarto"}

    def test_empty_data_fails_loud(self, db: DiscoveryDB):
        s = db.begin_scan("zigbee")
        with pytest.raises(ValueError, match="empty present set"):
            db.save_zigbee(s, {})


# -- Schema upgrades & the v4 blob conversion ---------------------------------

_OLD_BLOB_DDL = (
    "CREATE TABLE {name} ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " scan_id INTEGER NOT NULL REFERENCES scans(id),"
    " hostname TEXT NOT NULL,"
    " data_json TEXT NOT NULL)"
)


def _make_old_db(path: Path, version: int) -> sqlite3.Connection:
    """Build a pre-v4 database from scratch, as old code created it."""
    import sqlite3 as _sqlite3

    conn = _sqlite3.connect(str(path), isolation_level=None)
    conn.execute(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " scan_type TEXT NOT NULL, started_at TEXT NOT NULL,"
        " finished_at TEXT, host_count INTEGER, changed_count INTEGER,"
        " metadata TEXT)"
    )
    conn.execute("CREATE TABLE _meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute(
        "INSERT INTO _meta (key, value) VALUES ('schema_version', ?)",
        (str(version),),
    )
    tombstone_col = ", is_tombstone INTEGER NOT NULL DEFAULT 0" if version >= 2 else ""
    conn.execute(
        "CREATE TABLE reachability (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " scan_id INTEGER NOT NULL REFERENCES scans(id),"
        " hostname TEXT NOT NULL, interface_idx INTEGER NOT NULL,"
        " ip TEXT NOT NULL, is_reachable INTEGER NOT NULL,"
        " transmitted INTEGER NOT NULL, received INTEGER NOT NULL,"
        f" rtt_avg_ms REAL{tombstone_col})"
    )
    blob_tables = ["snmp_data", "bridge_data", "nsdp_data", "tasmota_data"]
    if version >= 3:
        blob_tables.append("zigbee_data")
    for name in blob_tables:
        conn.execute(_OLD_BLOB_DDL.format(name=name))
    return conn


def _finished_scan(conn: sqlite3.Connection, scan_type: str) -> int:
    cur = conn.execute(
        "INSERT INTO scans (scan_type, started_at, finished_at, host_count,"
        " changed_count) VALUES (?, '2026-06-01T00:00:00+00:00',"
        " '2026-06-01T00:01:00+00:00', 1, 1)",
        (scan_type,),
    )
    return cur.lastrowid


def _blob_row(
    conn: sqlite3.Connection, table: str, scan_id: int, key: str, doc,
) -> None:
    import json

    conn.execute(
        f"INSERT INTO {table} (scan_id, hostname, data_json)"  # noqa: S608
        " VALUES (?, ?, ?)",
        (scan_id, key, json.dumps(doc, sort_keys=True)),
    )


class TestSchemaUpgrade:
    def _table_names(self, d: DiscoveryDB) -> set[str]:
        return {
            r[0] for r in d.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    def _assert_current(self, d: DiscoveryDB) -> None:
        version = d.connection.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert int(version) == DiscoveryDB.SCHEMA_VERSION
        tables = self._table_names(d)
        assert {"zigbee_sites", "zigbee_devices", "snmp_hosts",
                "bridge_switches", "nsdp_switches", "tasmota_devices"} <= tables
        assert not {t for t in tables if t.endswith("_data")}

    def test_rw_open_upgrades_v1(self, tmp_path: Path):
        path = tmp_path / "v1.db"
        _make_old_db(path, version=1).close()

        d = DiscoveryDB(path)  # read-write open applies all upgrades
        cols = [r[1] for r in d.connection.execute(
            "PRAGMA table_info(reachability)"
        )]
        assert "is_tombstone" in cols  # v2 step
        self._assert_current(d)       # v3 + v4 steps
        d.close()

    def test_rw_open_upgrades_v3(self, tmp_path: Path):
        path = tmp_path / "v3.db"
        _make_old_db(path, version=3).close()

        d = DiscoveryDB(path)
        self._assert_current(d)
        d.close()

    def test_read_only_open_of_old_db_fails_loud(self, tmp_path: Path):
        from gdoc2netcfg.storage.base import SchemaVersionError

        path = tmp_path / "v3.db"
        _make_old_db(path, version=3).close()

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


class TestV4BlobConversion:
    """The v4 upgrade converts every stored blob into structured rows,
    preserving scan_ids (history) and the exact load_latest_* results."""

    def _build_v3_with_data(self, path: Path) -> dict:
        conn = _make_old_db(path, version=3)
        expected: dict = {}

        s = _finished_scan(conn, "snmp")
        _blob_row(conn, "snmp_data", s, "printer1", _snmp_doc("old-name"))
        s2 = _finished_scan(conn, "snmp")
        _blob_row(conn, "snmp_data", s2, "printer1", _snmp_doc("new-name"))
        expected["snmp"] = {"printer1": _snmp_doc("new-name")}

        s = _finished_scan(conn, "bridge")
        _blob_row(conn, "bridge_data", s, "sw1", _bridge_doc())
        old_bridge = _bridge_doc()
        del old_bridge["port_statistics"]  # pre-port_statistics generation
        _blob_row(conn, "bridge_data", s, "sw-old", old_bridge)
        expected["bridge"] = {"sw1": _bridge_doc(), "sw-old": old_bridge}

        s = _finished_scan(conn, "nsdp")
        _blob_row(conn, "nsdp_data", s, "sw-iot", _nsdp_doc_full())
        _blob_row(conn, "nsdp_data", s, "sw-min",
                  {"model": "GS108E", "mac": "AA:BB:CC:DD:EE:02"})
        expected["nsdp"] = {
            "sw-iot": _nsdp_doc_full(),
            "sw-min": {"model": "GS108E", "mac": "AA:BB:CC:DD:EE:02"},
        }

        s = _finished_scan(conn, "tasmota")
        _blob_row(conn, "tasmota_data", s, "plug1", _tasmota_doc("plug1"))
        _blob_row(conn, "tasmota_data", s, "_unknown/10.1.90.42",
                  _tasmota_doc("mystery"))
        expected["tasmota"] = {
            "plug1": _tasmota_doc("plug1"),
            "_unknown/10.1.90.42": _tasmota_doc("mystery"),
        }

        # Zigbee history in all three formats:
        # scan A — legacy flat keys (device + bridge rows);
        # scan B — site documents + null rows retiring the legacy keys.
        sa = _finished_scan(conn, "zigbee")
        _blob_row(conn, "zigbee_data", sa, "0x01",
                  _zb_device("welland", "0x01", availability="offline"))
        _blob_row(conn, "zigbee_data", sa, "0x99",
                  _zb_device("welland", "0x99"))
        _blob_row(conn, "zigbee_data", sa, "_bridge/welland",
                  _zb_bridge("welland"))
        sb = _finished_scan(conn, "zigbee")
        welland_doc = _zb_site_doc(
            "welland",
            _zb_device("welland", "0x01"),
            _zb_device("welland", "0x99"),
        )
        _blob_row(conn, "zigbee_data", sb, "welland", welland_doc)
        _blob_row(conn, "zigbee_data", sb, "0x01", None)
        _blob_row(conn, "zigbee_data", sb, "0x99", None)
        _blob_row(conn, "zigbee_data", sb, "_bridge/welland", None)
        expected["zigbee"] = {"welland": welland_doc}

        conn.close()
        return expected

    def test_conversion_preserves_latest_state(self, tmp_path: Path):
        path = tmp_path / "v3.db"
        expected = self._build_v3_with_data(path)

        d = DiscoveryDB(path)  # rw open runs the v4 conversion
        assert d.load_latest_snmp() == expected["snmp"]
        assert d.load_latest_bridge() == expected["bridge"]
        assert d.load_latest_nsdp() == expected["nsdp"]
        assert d.load_latest_tasmota() == expected["tasmota"]
        assert d.load_latest_zigbee() == expected["zigbee"]
        d.close()

    def test_conversion_preserves_history(self, tmp_path: Path):
        path = tmp_path / "v3.db"
        self._build_v3_with_data(path)

        d = DiscoveryDB(path)
        names = [r[0] for r in d.connection.execute(
            "SELECT sys_name FROM snmp_hosts WHERE hostname = 'printer1' "
            "ORDER BY id"
        )]
        assert names == ["old-name", "new-name"]
        # The legacy zigbee device rows survive under their old scans.
        avail = [r[0] for r in d.connection.execute(
            "SELECT availability FROM zigbee_devices "
            "WHERE site = 'welland' AND ieee_address = '0x01' ORDER BY id"
        )]
        assert avail == ["offline", "online"]
        d.close()

    def test_legacy_ghost_device_self_heals_on_next_save(self, tmp_path: Path):
        """A legacy device row whose (site, ieee) never reappears in a
        site document is visible after conversion (its latest row is
        live data) — and the next save tombstones it, because the site's
        document is authoritative."""
        path = tmp_path / "v3.db"
        conn = _make_old_db(path, version=3)
        sa = _finished_scan(conn, "zigbee")
        _blob_row(conn, "zigbee_data", sa, "0xghost",
                  _zb_device("welland", "0xghost"))
        _blob_row(conn, "zigbee_data", sa, "_bridge/welland",
                  _zb_bridge("welland"))
        sb = _finished_scan(conn, "zigbee")
        _blob_row(conn, "zigbee_data", sb, "welland",
                  _zb_site_doc("welland", _zb_device("welland", "0x01")))
        _blob_row(conn, "zigbee_data", sb, "0xghost", None)
        conn.close()

        d = DiscoveryDB(path)
        loaded = d.load_latest_zigbee()
        assert set(loaded["welland"]["devices"]) == {"0x01", "0xghost"}

        s = d.begin_scan("zigbee")
        changed = d.save_zigbee(s, {
            "welland": _zb_site_doc("welland", _zb_device("welland", "0x01")),
        })
        d.finish_scan(s, host_count=1, changed_count=changed)
        assert changed == 1  # the ghost's tombstone
        assert set(d.load_latest_zigbee()["welland"]["devices"]) == {"0x01"}
        d.close()

    def test_unconvertible_blob_rolls_back(self, tmp_path: Path):
        path = tmp_path / "v3.db"
        conn = _make_old_db(path, version=3)
        s = _finished_scan(conn, "snmp")
        _blob_row(conn, "snmp_data", s, "weird", {"not": "a snmp doc"})
        conn.close()

        with pytest.raises(ValueError, match="snmp"):
            DiscoveryDB(path)

        # Rolled back: still v3, blob data intact.
        conn = sqlite3.connect(str(path))
        version = conn.execute(
            "SELECT value FROM _meta WHERE key = 'schema_version'"
        ).fetchone()[0]
        assert int(version) == 3
        assert conn.execute(
            "SELECT COUNT(*) FROM snmp_data"
        ).fetchone()[0] == 1
        conn.close()
