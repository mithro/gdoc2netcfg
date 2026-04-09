"""Tests for the ConfigDB storage layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from gdoc2netcfg.storage.config_db import ConfigDB


@pytest.fixture()
def db(tmp_path: Path) -> ConfigDB:
    d = ConfigDB(tmp_path / "config.db")
    yield d
    d.close()


def _make_record(
    machine: str = "desktop",
    mac: str = "aa:bb:cc:dd:ee:ff",
    ip: str = "10.1.10.100",
    interface: str = "",
    sheet_name: str = "network",
    row_number: int = 2,
    site: str = "",
    extra: dict | None = None,
) -> dict:
    return {
        "sheet_name": sheet_name,
        "row_number": row_number,
        "machine": machine,
        "mac_address": mac,
        "ip": ip,
        "interface": interface,
        "site": site,
        "extra": extra or {},
    }


def _make_vlan(
    vlan_id: int = 10,
    name: str = "int",
    ip_range: str = "10.1.10.X",
    netmask: str = "255.255.255.0",
    cidr: str = "/24",
    color: str = "",
    description: str = "Internal",
) -> dict:
    return {
        "id": vlan_id,
        "name": name,
        "ip_range": ip_range,
        "netmask": netmask,
        "cidr": cidr,
        "color": color,
        "description": description,
    }


# -- CSV snapshots ---------------------------------------------------------

class TestCSVSnapshots:
    def test_save_and_load(self, db: ConfigDB):
        scan_id = db.begin_scan("csv_fetch")
        db.save_csv(scan_id, "network", "Machine,MAC\ndesktop,aa:bb")
        db.finish_scan(scan_id, host_count=1, changed_count=1)

        result = db.load_latest_csv("network")
        assert result == "Machine,MAC\ndesktop,aa:bb"

    def test_load_missing_returns_none(self, db: ConfigDB):
        assert db.load_latest_csv("nonexistent") is None

    def test_has_csv(self, db: ConfigDB):
        assert not db.has_csv("network")
        scan_id = db.begin_scan("csv_fetch")
        db.save_csv(scan_id, "network", "data")
        db.finish_scan(scan_id, host_count=1, changed_count=1)
        assert db.has_csv("network")

    def test_latest_csv_is_most_recent(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_csv(s1, "network", "old")
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        db.save_csv(s2, "network", "new")
        db.finish_scan(s2, host_count=1, changed_count=1)

        assert db.load_latest_csv("network") == "new"

    def test_unfinished_scan_not_loaded(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_csv(s1, "network", "finished")
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        db.save_csv(s2, "network", "unfinished")
        # s2 not finished

        assert db.load_latest_csv("network") == "finished"

    def test_csv_always_stored(self, db: ConfigDB):
        """CSV snapshots are NOT delta-based — every fetch stores the text."""
        csv_text = "Machine,MAC\ndesktop,aa:bb"
        s1 = db.begin_scan("csv_fetch")
        db.save_csv(s1, "network", csv_text)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        db.save_csv(s2, "network", csv_text)  # identical text
        db.finish_scan(s2, host_count=1, changed_count=0)

        history = db.csv_history("network")
        assert len(history) == 2  # both stored

    def test_csv_history(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_csv(s1, "network", "v1")
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        db.save_csv(s2, "network", "v2")
        db.finish_scan(s2, host_count=1, changed_count=1)

        history = db.csv_history("network")
        assert len(history) == 2
        assert history[0][1] == "v2"  # newest first
        assert history[1][1] == "v1"

    def test_csv_history_since_filter(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_csv(s1, "network", "v1")
        db.finish_scan(s1, host_count=1, changed_count=1)

        # Filter with future timestamp excludes everything
        history = db.csv_history("network", since="2099-01-01T00:00:00")
        assert history == []


# -- Device records (delta-based) ------------------------------------------

class TestDeviceRecords:
    def test_save_and_load(self, db: ConfigDB):
        scan_id = db.begin_scan("csv_fetch")
        records = [_make_record()]
        changed = db.save_device_records(scan_id, records)
        db.finish_scan(scan_id, host_count=1, changed_count=changed)

        assert changed == 1
        loaded = db.load_latest_device_records()
        assert loaded is not None
        assert len(loaded) == 1
        assert loaded[0]["machine"] == "desktop"
        assert loaded[0]["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert loaded[0]["ip"] == "10.1.10.100"

    def test_load_returns_none_with_no_scans(self, db: ConfigDB):
        assert db.load_latest_device_records() is None

    def test_delta_no_change(self, db: ConfigDB):
        """Saving identical records twice produces changed_count=0."""
        records = [_make_record()]

        s1 = db.begin_scan("csv_fetch")
        changed1 = db.save_device_records(s1, records)
        db.finish_scan(s1, host_count=1, changed_count=changed1)
        assert changed1 == 1

        s2 = db.begin_scan("csv_fetch")
        changed2 = db.save_device_records(s2, records)
        db.finish_scan(s2, host_count=1, changed_count=changed2)
        assert changed2 == 0

    def test_delta_detects_ip_change(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(s1, [_make_record(ip="10.1.10.100")])
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_device_records(
            s2, [_make_record(ip="10.1.10.200")]
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

        loaded = db.load_latest_device_records()
        assert loaded[0]["ip"] == "10.1.10.200"

    def test_delta_detects_mac_change(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(s1, [_make_record(mac="aa:bb:cc:dd:ee:ff")])
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_device_records(
            s2, [_make_record(mac="11:22:33:44:55:66")]
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_delta_detects_extra_change(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(
            s1, [_make_record(extra={"Password": "old"})]
        )
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_device_records(
            s2, [_make_record(extra={"Password": "new"})]
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_extra_json_key_order_irrelevant(self, db: ConfigDB):
        """Extra dicts with same keys in different order are equal."""
        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(
            s1, [_make_record(extra={"a": "1", "b": "2"})]
        )
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        # Same content, different insertion order
        changed = db.save_device_records(
            s2, [_make_record(extra={"b": "2", "a": "1"})]
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_multiple_records_partial_change(self, db: ConfigDB):
        """Only changed records produce new rows."""
        records = [
            _make_record(machine="server1", ip="10.1.10.1"),
            _make_record(machine="server2", ip="10.1.10.2"),
        ]

        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(s1, records)
        db.finish_scan(s1, host_count=2, changed_count=2)

        # Change only server2
        records2 = [
            _make_record(machine="server1", ip="10.1.10.1"),  # same
            _make_record(machine="server2", ip="10.1.10.99"),  # changed
        ]
        s2 = db.begin_scan("csv_fetch")
        changed = db.save_device_records(s2, records2)
        db.finish_scan(s2, host_count=2, changed_count=changed)
        assert changed == 1

        loaded = db.load_latest_device_records()
        by_machine = {r["machine"]: r for r in loaded}
        assert by_machine["server1"]["ip"] == "10.1.10.1"
        assert by_machine["server2"]["ip"] == "10.1.10.99"

    def test_new_machine_added(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(s1, [_make_record(machine="server1")])
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_device_records(s2, [
            _make_record(machine="server1"),
            _make_record(machine="server2", ip="10.1.10.2"),
        ])
        db.finish_scan(s2, host_count=2, changed_count=changed)
        assert changed == 1  # only server2 is new

        loaded = db.load_latest_device_records()
        assert len(loaded) == 2

    def test_interface_key_separates_records(self, db: ConfigDB):
        """Same machine with different interfaces are distinct records."""
        records = [
            _make_record(machine="server", interface=""),
            _make_record(machine="server", interface="bmc", ip="10.1.10.99"),
        ]
        s1 = db.begin_scan("csv_fetch")
        changed = db.save_device_records(s1, records)
        db.finish_scan(s1, host_count=2, changed_count=changed)
        assert changed == 2

        loaded = db.load_latest_device_records()
        assert len(loaded) == 2

    def test_device_history(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(s1, [_make_record(ip="10.1.10.1")])
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        db.save_device_records(s2, [_make_record(ip="10.1.10.2")])
        db.finish_scan(s2, host_count=1, changed_count=1)

        history = db.device_history("desktop")
        assert len(history) == 2
        assert history[0][1]["ip"] == "10.1.10.2"  # newest first
        assert history[1][1]["ip"] == "10.1.10.1"

    def test_extra_round_trip(self, db: ConfigDB):
        """Extra dict survives save/load round trip."""
        extra = {"Password": "secret", "SNMP Community": "public"}
        s1 = db.begin_scan("csv_fetch")
        db.save_device_records(s1, [_make_record(extra=extra)])
        db.finish_scan(s1, host_count=1, changed_count=1)

        loaded = db.load_latest_device_records()
        assert loaded[0]["extra"] == extra


# -- VLAN definitions (delta-based) ----------------------------------------

class TestVLANDefinitions:
    def test_save_and_load(self, db: ConfigDB):
        scan_id = db.begin_scan("csv_fetch")
        vlans = [_make_vlan()]
        changed = db.save_vlan_definitions(scan_id, vlans)
        db.finish_scan(scan_id, host_count=1, changed_count=changed)

        assert changed == 1
        loaded = db.load_latest_vlan_definitions()
        assert loaded is not None
        assert len(loaded) == 1
        assert loaded[0]["id"] == 10
        assert loaded[0]["name"] == "int"
        assert loaded[0]["cidr"] == "/24"

    def test_load_returns_none_with_no_scans(self, db: ConfigDB):
        assert db.load_latest_vlan_definitions() is None

    def test_delta_no_change(self, db: ConfigDB):
        vlans = [_make_vlan()]
        s1 = db.begin_scan("csv_fetch")
        db.save_vlan_definitions(s1, vlans)
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_vlan_definitions(s2, vlans)
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 0

    def test_delta_detects_name_change(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_vlan_definitions(s1, [_make_vlan(name="int")])
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_vlan_definitions(
            s2, [_make_vlan(name="internal")]
        )
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_delta_detects_cidr_change(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_vlan_definitions(s1, [_make_vlan(cidr="/24")])
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_vlan_definitions(s2, [_make_vlan(cidr="/21")])
        db.finish_scan(s2, host_count=1, changed_count=changed)
        assert changed == 1

    def test_new_vlan_added(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_vlan_definitions(s1, [_make_vlan(vlan_id=10)])
        db.finish_scan(s1, host_count=1, changed_count=1)

        s2 = db.begin_scan("csv_fetch")
        changed = db.save_vlan_definitions(s2, [
            _make_vlan(vlan_id=10),
            _make_vlan(vlan_id=20, name="net"),
        ])
        db.finish_scan(s2, host_count=2, changed_count=changed)
        assert changed == 1  # only VLAN 20 is new

    def test_multiple_vlans_ordered_by_id(self, db: ConfigDB):
        s1 = db.begin_scan("csv_fetch")
        db.save_vlan_definitions(s1, [
            _make_vlan(vlan_id=20, name="net"),
            _make_vlan(vlan_id=10, name="int"),
        ])
        db.finish_scan(s1, host_count=2, changed_count=2)

        loaded = db.load_latest_vlan_definitions()
        assert [v["id"] for v in loaded] == [10, 20]
