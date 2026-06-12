"""Direct tests for update_zigbee_sheet's per-site row ownership."""

from unittest.mock import patch

import pytest

from gdoc2netcfg.config import (
    CacheConfig,
    PipelineConfig,
    SheetsConfig,
    ZigbeeConfig,
    ZigbeeSiteConfig,
)
from gdoc2netcfg.models.network import Site
from gdoc2netcfg.supplements.zigbee import ZigbeeDevice
from gdoc2netcfg.supplements.zigbee_sheet import update_zigbee_sheet

HEADER = [
    "Site", "Type", "Entity Name", "Description", "Friendly Name",
    "State", "", "Model", "IEEE Address", "Power Source", "Connected Via",
]


class FakeWorksheet:
    def __init__(self, rows):
        self.rows = rows
        self.batch_updates: list = []
        self.appended: list = []

    def get_all_values(self):
        return self.rows

    def batch_update(self, updates):
        self.batch_updates.extend(updates)

    def append_rows(self, rows):
        self.appended.extend(rows)


class FakeClient:
    def __init__(self, ws):
        self._ws = ws

    def open_by_url(self, url):
        return self

    def worksheet(self, name):
        return self._ws


def _config(*site_names: str) -> PipelineConfig:
    return PipelineConfig(
        site=Site(name="test", domain="test.example.com"),
        spreadsheet_url="https://docs.google.com/spreadsheets/d/x/edit",
        cache=CacheConfig(),
        sheets_config=SheetsConfig(credentials_file="client_secret.json"),
        zigbee=ZigbeeConfig(
            sites=[
                ZigbeeSiteConfig(name=n, mqtt_host=f"mqtt.{n}.example")
                for n in site_names
            ],
        ),
    )


def _device(site: str, ieee: str, **overrides) -> ZigbeeDevice:
    fields = {
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
        "date_code": "",
        "last_seen": None,
        "link_quality": 80,
        "availability": "online",
        "network_address": 1234,
    }
    fields.update(overrides)
    return ZigbeeDevice(**fields)


def _run(config, devices, rows, dry_run=False):
    ws = FakeWorksheet(rows)
    with patch(
        "gdoc2netcfg.supplements.zigbee_sheet.get_gspread_client",
        return_value=FakeClient(ws),
    ):
        written = update_zigbee_sheet(
            config, devices, {s.name: None for s in config.zigbee.sites},
            dry_run=dry_run, verbose=True,
        )
    return written, ws


def _row(site, ieee, cells=None):
    row = [site, "Temp Sensor", "kitchen_temp", "", "kitchen_temp",
           "Online", "", "WSDCGQ12LM", ieee, "Battery", ""]
    if cells:
        for idx, val in cells.items():
            row[idx] = val
    return row


class TestPerSiteKeying:
    def test_same_ieee_two_sites_hits_the_right_row(self):
        """(Site, IEEE) keying: the welland run updates the welland row
        even though a monarto row shares the IEEE."""
        monarto_row = _row("monarto", "0x01")
        rows = [HEADER, monarto_row, _row("welland", "0x01", cells={5: "Offline"})]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 1
        assert len(ws.batch_updates) == 1
        # Row 3 of the sheet (header + monarto row above it)
        assert ws.batch_updates[0]["range"].startswith("A3:")
        assert ws.batch_updates[0]["values"][0][0] == "welland"
        assert ws.appended == []

    def test_other_site_rows_untouched(self):
        """A run never writes rows owned by another site — the same
        IEEE under another site appends a NEW row (the duplication)."""
        monarto_row = _row("monarto", "0x01")
        rows = [HEADER, monarto_row]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 1
        assert ws.batch_updates == []
        assert len(ws.appended) == 1
        assert ws.appended[0][0] == "welland"
        assert ws.rows[1] == monarto_row  # byte-for-byte untouched

    def test_site_match_is_case_insensitive(self):
        rows = [HEADER, _row("Welland", "0x01", cells={5: "Offline"})]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 1
        assert len(ws.batch_updates) == 1
        assert ws.appended == []

    def test_append_carries_site_and_blank_col_g(self):
        rows = [HEADER]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert ws.appended == [[
            "welland", "Temp Sensor", "kitchen_temp", "", "kitchen_temp",
            "Online", "", "WSDCGQ12LM", "0x01", "Battery", "",
        ]]

    def test_unchanged_row_is_not_rewritten(self):
        """Idempotence: a second run over current data writes nothing."""
        rows = [HEADER, _row("welland", "0x01")]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert written == 0
        assert ws.batch_updates == []
        assert ws.appended == []

    def test_multi_site_run_mixes_update_and_append(self):
        """A run configured with both sites updates one site's stale row
        and appends the other's missing row in the same pass."""
        rows = [HEADER, _row("welland", "0x01", cells={5: "Offline"})]
        written, ws = _run(
            _config("welland", "monarto"),
            [_device("welland", "0x01"), _device("monarto", "0x01")],
            rows,
        )
        assert written == 2
        assert len(ws.batch_updates) == 1
        assert ws.batch_updates[0]["values"][0][0] == "welland"
        assert len(ws.appended) == 1
        assert ws.appended[0][0] == "monarto"

    def test_update_preserves_col_g_and_existing_type(self):
        """Hand-maintained column G survives an update, and an
        unrecognised model falls back to the sheet's existing Type."""
        row = _row("welland", "0x01", cells={1: "Custom Type", 5: "Offline", 6: "serial-123"})
        rows = [HEADER, row]
        device = _device(
            "welland", "0x01",
            model="Mystery Gadget 3000", model_id="MG3000",
        )
        written, ws = _run(_config("welland"), [device], rows)
        assert written == 1
        new_row = ws.batch_updates[0]["values"][0]
        assert new_row[6] == "serial-123"      # column G preserved
        assert new_row[1] == "Custom Type"     # Type fallback to sheet value
        assert new_row[7] == "MG3000"          # model_id written

    def test_connected_via_uses_bridge_info(self):
        """A real bridge info renders 'coordinator (site)' in column K."""
        from gdoc2netcfg.supplements.zigbee import ZigbeeBridgeInfo

        bridge = ZigbeeBridgeInfo(
            site="welland", z2m_version="1.38.0",
            coordinator_ieee="0x00aa", coordinator_type="ConBee II",
            channel=15, pan_id="0x1a62",
        )
        ws = FakeWorksheet([HEADER])
        with patch(
            "gdoc2netcfg.supplements.zigbee_sheet.get_gspread_client",
            return_value=FakeClient(ws),
        ):
            written = update_zigbee_sheet(
                _config("welland"), [_device("welland", "0x01")],
                {"welland": bridge}, verbose=False,
            )
        assert written == 1
        assert ws.appended[0][10] == "ConBee II (welland)"


class TestWarnings:
    def test_duplicate_in_scope_rows_warns_first_wins(self, capsys):
        rows = [
            HEADER,
            _row("welland", "0x01", cells={5: "Offline"}),
            _row("welland", "0x01", cells={5: "Offline"}),
        ]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        assert "duplicate rows for site=welland ieee=0x01" in capsys.readouterr().err
        assert written == 1
        assert ws.batch_updates[0]["range"].startswith("A2:")  # first row won

    def test_blank_site_row_with_matching_ieee_warns(self, capsys):
        rows = [HEADER, _row("", "0x01")]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
        )
        err = capsys.readouterr().err
        assert "blank" in err and "0x01" in err
        assert ws.rows[1][0] == ""  # legacy row untouched
        assert len(ws.appended) == 1  # device still got its own row


class TestErrors:
    def test_no_sites_configured_raises(self):
        with pytest.raises(RuntimeError, match="No zigbee sites configured"):
            _run(_config(), [], [HEADER])

    def test_device_outside_scope_raises(self):
        with pytest.raises(RuntimeError, match="not in this run's configured"):
            _run(_config("welland"), [_device("monarto", "0x01")], [HEADER])

    def test_missing_site_column_raises(self):
        header = [c for c in HEADER if c != "Site"]
        with pytest.raises(RuntimeError, match="does not match the expected layout"):
            _run(_config("welland"), [_device("welland", "0x01")], [header])

    def test_dry_run_writes_nothing(self):
        rows = [HEADER]
        written, ws = _run(
            _config("welland"), [_device("welland", "0x01")], rows,
            dry_run=True,
        )
        assert written == 1
        assert ws.appended == [] and ws.batch_updates == []

    def test_reordered_columns_raise(self):
        header = list(HEADER)
        header[0], header[1] = header[1], header[0]  # swap Site and Type
        with pytest.raises(RuntimeError, match="does not match the expected layout"):
            _run(_config("welland"), [_device("welland", "0x01")], [header])

    def test_inner_column_reorder_raises(self):
        """A reorder confined to columns C-H (the old anchors untouched)
        must still refuse to write — it would corrupt column G serials."""
        header = list(HEADER)
        header[3], header[6] = header[6], header[3]  # swap Description and the serial column
        with pytest.raises(RuntimeError, match="does not match the expected layout"):
            _run(_config("welland"), [_device("welland", "0x01")], [header])
