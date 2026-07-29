"""Tests for CSV parser."""

from pathlib import Path

import pytest

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

        assert len(records) == 2

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


class TestWifiSiteCarryForward:
    """WiFi-sheet Site carry-forward: a merged Site cell exports its value
    only on the anchor row, so a blank Site row must inherit the Site of
    the immediately preceding row when the machine name is unchanged
    (contiguous block) -- but ONLY on the wifi sheet (see the inline
    comment above the row loop in parser.py::parse_csv for the rationale).
    """

    # Shared CSV shape used by every test in this class (9 data rows):
    #   row0 puckA  site=welland   (explicit anchor)
    #   row1 puckA  site=<blank>   -> inherits welland (a)
    #   row2 puckA  site=<blank>   -> inherits welland too -- a 3rd row in
    #                                 the SAME block, proving the inherited
    #                                 value keeps propagating past the
    #                                 first inheriting row (the live
    #                                 OpenMesh blocks are anchor + 6 blanks
    #                                 after the formatter's merge, so
    #                                 propagation past row 2 is
    #                                 load-bearing, not incidental)
    #   row3 puckB  site=<blank>   -> machine changed, no inherit (b)
    #   row4 puckB  site=<blank>   -> still blank throughout (c)
    #   row5 <blank machine>, site=stray  -> explicit value always kept,
    #                                 regardless of machine being blank
    #   row6 <blank machine>, site=<blank> -> must stay blank: row6 and
    #                                 row5 share the SAME (blank) machine
    #                                 value, so this pins that inheritance
    #                                 requires a genuinely non-blank
    #                                 machine name, not mere equality with
    #                                 the previous row's machine
    #   row7 puckC  site=welland   (explicit)
    #   row8 puckC  site=monarto   -> explicit value kept, not overwritten
    #                                 by inheritance (e)
    CSV_TEXT = (
        "Machine,MAC Address,IP,Site\n"
        "puckA,aa:bb:cc:dd:ee:01,10.1.4.1,welland\n"
        "puckA,aa:bb:cc:dd:ee:02,10.1.4.2,\n"
        "puckA,aa:bb:cc:dd:ee:03,10.1.4.3,\n"
        "puckB,aa:bb:cc:dd:ee:04,10.1.4.4,\n"
        "puckB,aa:bb:cc:dd:ee:05,10.1.4.5,\n"
        ",aa:bb:cc:dd:ee:06,10.1.4.6,stray\n"
        ",aa:bb:cc:dd:ee:07,10.1.4.7,\n"
        "puckC,aa:bb:cc:dd:ee:08,10.1.4.8,welland\n"
        "puckC,aa:bb:cc:dd:ee:09,10.1.4.9,monarto\n"
    )

    def test_blank_site_inherits_within_same_machine_block(self):
        """(a) A blank-Site row inherits the previous row's Site when the
        machine name matches (wifi sheet), and the inherited value keeps
        propagating to a THIRD row in the same block (not just the row
        immediately after the anchor) -- mutation coverage: a broken
        tracker that stores the pre-inheritance value instead of the
        resolved one would pass row1 but fail row2."""
        records = parse_csv(self.CSV_TEXT, "wifi")
        assert records[0].machine == "puckA"
        assert records[0].site == "welland"
        assert records[1].machine == "puckA"
        assert records[1].site == "welland"
        assert records[2].machine == "puckA"
        assert records[2].site == "welland"

    def test_no_inheritance_across_machine_change(self):
        """(b) A blank-Site row does NOT inherit across a machine change,
        even though the immediately preceding row has a (possibly
        inherited) Site value."""
        records = parse_csv(self.CSV_TEXT, "wifi")
        assert records[3].machine == "puckB"
        assert records[3].site == ""

    def test_first_row_blank_block_stays_blank_throughout(self):
        """(c) When the FIRST row of a machine block is blank, the block
        stays blank throughout -- there is nothing to inherit."""
        records = parse_csv(self.CSV_TEXT, "wifi")
        assert records[3].machine == "puckB"
        assert records[3].site == ""
        assert records[4].machine == "puckB"
        assert records[4].site == ""

    def test_blank_machine_rows_do_not_inherit_from_each_other(self):
        """Blank-Machine rows must never participate in carry-forward,
        even between themselves. row5 and row6 both have an empty Machine
        field, i.e. an empty string that trivially equals itself -- a
        naive `machine == prev_machine` check (without also requiring
        `machine` to be truthy) would let row6 inherit row5's explicit
        'stray' Site. This pins the guard that blocks that."""
        records = parse_csv(self.CSV_TEXT, "wifi")
        assert records[5].machine == ""
        assert records[5].site == "stray"
        assert records[6].machine == ""
        assert records[6].site == ""

    def test_explicit_site_on_later_row_is_kept(self):
        """(e) An explicit, different Site on a later same-machine row is
        kept as-is -- only blank cells inherit."""
        records = parse_csv(self.CSV_TEXT, "wifi")
        assert records[7].machine == "puckC"
        assert records[7].site == "welland"
        assert records[8].machine == "puckC"
        assert records[8].site == "monarto"

    def test_network_sheet_does_not_inherit(self):
        """(d) The SAME csv shape parsed as sheet_name='network' keeps
        strictly per-row Site semantics -- no carry-forward."""
        records = parse_csv(self.CSV_TEXT, "network")
        assert [r.site for r in records] == [
            "welland",
            "",  # would be "welland" if inherited
            "",  # would be "welland" if inherited (row propagated twice)
            "",
            "",
            "stray",
            "",  # would be "stray" if inherited
            "welland",
            "monarto",
        ]

    @pytest.mark.parametrize("sheet_name", ["wifi", "WiFi", "WIFI"])
    def test_sheet_name_match_is_case_insensitive(self, sheet_name):
        """The wifi-sheet gate (`sheet_name.lower() == "wifi"`) must fire
        regardless of how the caller capitalizes the sheet name."""
        csv_text = (
            "Machine,MAC Address,IP,Site\n"
            "puckA,aa:bb:cc:dd:ee:01,10.1.4.1,welland\n"
            "puckA,aa:bb:cc:dd:ee:02,10.1.4.2,\n"
        )
        records = parse_csv(csv_text, sheet_name)
        assert records[1].site == "welland"
