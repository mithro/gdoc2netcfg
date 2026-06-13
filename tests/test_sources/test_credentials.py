"""Tests for credential column stripping and extraction."""

from __future__ import annotations

import csv
import io

from gdoc2netcfg.sources.credentials import (
    credential_field_names,
    extract_credentials,
    strip_credential_columns,
)


def test_field_names_are_flattened_credential_types():
    names = credential_field_names()
    assert names == ["Password", "SNMP Community", "IPMI Username", "IPMI Password"]


def test_strip_removes_credential_columns():
    csv_text = (
        "Machine,MAC Address,IP,Password,Notes\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,secret,hi\n"
    )
    stripped, present = strip_credential_columns(csv_text)
    assert present == ["Password"]
    rows = list(csv.reader(io.StringIO(stripped)))
    assert rows[0] == ["Machine", "MAC Address", "IP", "Notes"]
    assert rows[1] == ["switch1", "aa:bb:cc:dd:ee:01", "10.1.30.1", "hi"]
    assert "secret" not in stripped


def test_strip_handles_banner_row_before_header():
    # Row 0 is a banner (IPv6 prefix); header is row 1 (find_header_row).
    csv_text = (
        ",,,,2001:db8::,,\n"
        "Machine,MAC Address,IP,Password,Notes\n"
        "switch1,aa:bb:cc:dd:ee:01,10.1.30.1,secret,hi\n"
    )
    stripped, present = strip_credential_columns(csv_text)
    assert present == ["Password"]
    assert "secret" not in stripped
    rows = list(csv.reader(io.StringIO(stripped)))
    assert rows[1] == ["Machine", "MAC Address", "IP", "Notes"]


def test_strip_noop_when_no_credential_columns():
    csv_text = "Machine,MAC Address,IP,Notes\nx,aa:bb:cc:dd:ee:01,10.1.1.1,hi\n"
    stripped, present = strip_credential_columns(csv_text)
    assert present == []
    assert stripped == csv_text


def test_extract_credentials_keyed_by_hostname():
    class _FakeHost:
        def __init__(self, hostname, extra):
            self.hostname = hostname
            self.extra = extra

    hosts = [
        _FakeHost("switch1", {"Password": "p1", "Notes": "x"}),
        _FakeHost("desktop", {"Notes": "y"}),  # no credentials
        _FakeHost("bmc.server1", {"IPMI Username": "admin", "IPMI Password": "pw"}),
    ]
    assert extract_credentials(hosts) == {
        "switch1": {"Password": "p1"},
        "bmc.server1": {"IPMI Username": "admin", "IPMI Password": "pw"},
    }
