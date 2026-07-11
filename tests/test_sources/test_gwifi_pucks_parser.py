"""Tests for the Google WiFi Pucks CSV parser."""

from pathlib import Path

import pytest

from gdoc2netcfg.sources.gwifi_pucks_parser import PuckRecord, parse_gwifi_pucks

FIXTURE = Path(__file__).parent.parent / "fixtures" / "gwifi_pucks.csv"


def fixture_csv() -> str:
    return FIXTURE.read_text()


class TestParseGwifiPucks:
    def test_filters_to_flashable_rows(self):
        # Row 1 is 'Google Original' (excluded), row 3 is OpenWRT but has no
        # serial/MAC (excluded); rows 4, 5, 12 survive.
        pucks = parse_gwifi_pucks(fixture_csv())
        assert [p.number for p in pucks] == [4, 5, 12]

    def test_names_zero_padded(self):
        pucks = parse_gwifi_pucks(fixture_csv())
        assert [p.name for p in pucks] == ["puck04", "puck05", "puck12"]

    def test_ips_deterministic_from_number(self):
        pucks = parse_gwifi_pucks(fixture_csv())
        assert [p.ip for p in pucks] == ["10.1.4.104", "10.1.4.105", "10.1.4.112"]

    def test_serials(self):
        pucks = parse_gwifi_pucks(fixture_csv())
        assert [p.serial for p in pucks] == [
            "2831HW00VZA", "2713HW003TB", "2831HW00WGD"]

    def test_eth_columns_used_when_present(self):
        by_num = {p.number: p for p in parse_gwifi_pucks(fixture_csv())}
        assert by_num[4].eth0 == "44:07:0B:01:87:B4"
        assert by_num[4].eth1 == "44:07:0B:01:87:B5"

    def test_eth1_derived_from_label_mac_when_columns_empty(self):
        # Row 5 has only the label MAC column: eth0 = MAC, eth1 = MAC + 1
        # (the fleet-verified pattern).
        by_num = {p.number: p for p in parse_gwifi_pucks(fixture_csv())}
        assert by_num[5].eth0 == "24:05:88:39:8A:08"
        assert by_num[5].eth1 == "24:05:88:39:8A:09"

    def test_macs_normalized_uppercase(self):
        csv_text = fixture_csv().replace(
            "24:05:88:39:8A:08", "24:05:88:39:8a:08")
        by_num = {p.number: p for p in parse_gwifi_pucks(csv_text)}
        assert by_num[5].eth0 == "24:05:88:39:8A:08"

    def test_duplicate_number_raises(self):
        row = "4,AC-1304,OpenWRT,DUPNUM,AA:BB:CC:DD:EE:01,x,y\n"
        with pytest.raises(ValueError, match="duplicate puck number"):
            parse_gwifi_pucks(fixture_csv() + row)

    def test_duplicate_serial_raises(self):
        row = "13,AC-1304,OpenWRT,2831HW00VZA,AA:BB:CC:DD:EE:01,x,y\n"
        with pytest.raises(ValueError, match="duplicate serial"):
            parse_gwifi_pucks(fixture_csv() + row)

    def test_number_over_99_raises(self):
        # IP scheme is 10.1.4.<100+NN>; NN > 99 would leave the /24.
        row = "100,AC-1304,OpenWRT,BIGNUM123456,AA:BB:CC:DD:EE:01,x,y\n"
        with pytest.raises(ValueError, match="puck number"):
            parse_gwifi_pucks(fixture_csv() + row)

    def test_eth1_derivation_wrap_raises(self):
        row = "13,AC-1304,OpenWRT,WRAPSERIAL01,AA:BB:CC:DD:EE:FF,x,y\n"
        with pytest.raises(ValueError, match="wrap"):
            parse_gwifi_pucks(fixture_csv() + row)

    def test_record_is_frozen(self):
        pucks = parse_gwifi_pucks(fixture_csv())
        with pytest.raises(AttributeError):
            pucks[0].name = "nope"

    def test_empty_csv(self):
        assert parse_gwifi_pucks("") == []

    def test_record_type(self):
        pucks = parse_gwifi_pucks(fixture_csv())
        assert all(isinstance(p, PuckRecord) for p in pucks)
