"""Tests for CSV parser."""

from pathlib import Path

from gdoc2netcfg.sources.parser import find_header_row, parse_csv

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestFindHeaderRow:
    def test_headers_on_first_row(self):
        rows = [["Machine", "MAC Address", "IP"], ["desktop", "aa:bb", "10.1.1.1"]]
        assert find_header_row(rows) == 0

    def test_headers_on_second_row(self):
        """Network sheet has metadata in row 1, headers in row 2."""
        rows = [
            ["IPv6 Prefix:", "2404:e80:a137:", "", ""],
            ["Machine", "MAC Address", "IP", "Interface"],
            ["desktop", "aa:bb:cc:dd:ee:ff", "10.1.10.1", "eth0"],
        ]
        assert find_header_row(rows) == 1

    def test_fallback_to_zero_if_not_found(self):
        rows = [["a", "b", "c"]]
        assert find_header_row(rows) == 0

    def test_empty_rows(self):
        assert find_header_row([]) == 0


class TestParseCSV:
    def test_parse_network_fixture(self):
        csv_text = (FIXTURES / "sample_network.csv").read_text()
        records = parse_csv(csv_text, "Network")

        assert len(records) == 5

        # First record: desktop eth0
        r0 = records[0]
        assert r0.machine == "desktop"
        assert r0.mac_address == "aa:bb:cc:dd:ee:01"
        assert r0.ip == "10.1.10.100"
        assert r0.interface == "eth0"
        assert r0.sheet_name == "Network"
        assert "Driver" in r0.extra
        assert r0.extra["Driver"] == "i225"

    def test_parse_iot_fixture(self):
        csv_text = (FIXTURES / "sample_iot.csv").read_text()
        records = parse_csv(csv_text, "IoT")

        assert len(records) == 3

        r0 = records[0]
        assert r0.machine == "thermostat"
        assert r0.mac_address == "aa:00:11:22:33:44"
        assert r0.ip == "10.1.90.10"
        assert r0.sheet_name == "IoT"
        assert r0.extra.get("Hardware") == "ESP32"

    def test_header_row_detection_with_prefix_row(self):
        """Network sheet has IPv6 prefix info in row 1."""
        csv_text = (FIXTURES / "sample_network.csv").read_text()
        records = parse_csv(csv_text, "Network")
        # Should not include the prefix row as a record
        for r in records:
            assert r.machine != "IPv6 Prefix:"

    def test_empty_csv(self):
        records = parse_csv("", "Empty")
        assert records == []

    def test_empty_rows_skipped(self):
        csv_text = "Machine,MAC Address,IP\n,,\ndesktop,aa:bb:cc:dd:ee:ff,10.1.10.1"
        records = parse_csv(csv_text, "Test")
        assert len(records) == 1
        assert records[0].machine == "desktop"

    def test_row_length_mismatch_skipped(self):
        csv_text = "Machine,MAC Address,IP\ndesktop,aa:bb:cc:dd:ee:ff"
        records = parse_csv(csv_text, "Test")
        assert len(records) == 0

    def test_row_number_is_1_based(self):
        csv_text = "Machine,MAC Address,IP\ndesktop,aa:bb:cc:dd:ee:ff,10.1.10.1"
        records = parse_csv(csv_text, "Test")
        assert records[0].row_number == 2  # Row 1 is header, data is row 2

    def test_interface_can_be_empty(self):
        csv_text = "Machine,MAC Address,IP,Interface\nserver,11:22:33:44:55:66,10.1.10.1,"
        records = parse_csv(csv_text, "Test")
        assert records[0].interface == ""

    def test_ipv4_column_name(self):
        """Some sheets use 'IPv4' instead of 'IP' for the address column."""
        csv_text = "Machine,MAC Address,IPv4\nserver,11:22:33:44:55:66,10.1.10.1"
        records = parse_csv(csv_text, "Test")
        assert records[0].ip == "10.1.10.1"

    def test_whitespace_stripping(self):
        csv_text = "Machine,MAC Address,IP\n  desktop  ,  aa:bb:cc:dd:ee:ff  ,  10.1.10.1  "
        records = parse_csv(csv_text, "Test")
        assert records[0].machine == "desktop"
        assert records[0].mac_address == "aa:bb:cc:dd:ee:ff"
        assert records[0].ip == "10.1.10.1"

    def test_site_column_populates_site_field(self):
        """An explicit 'Site' column is used for site filtering."""
        csv_text = "Machine,MAC Address,IP,Site\nserver,11:22:33:44:55:66,10.1.10.1,monarto"
        records = parse_csv(csv_text, "Test")
        assert records[0].site == "monarto"

    def test_location_column_not_used_as_site(self):
        """A 'Location' column must NOT be treated as a site filter."""
        csv_text = (
            "Machine,MAC Address,IP,Location\n"
            "plug1,11:22:33:44:55:66,10.1.90.1,Back Shed"
        )
        records = parse_csv(csv_text, "Test")
        assert records[0].site == ""
        assert records[0].extra.get("Location") == "Back Shed"
