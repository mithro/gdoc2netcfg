"""Tests for the shared Google Sheets client helper."""

import pytest

from gdoc2netcfg.config import SheetsConfig
from gdoc2netcfg.utils.gsheets import get_gspread_client


class TestGetGspreadClient:
    def test_no_credentials_configured_raises(self):
        with pytest.raises(RuntimeError, match=r"\[sheets\] section"):
            get_gspread_client(SheetsConfig())

    def test_missing_service_account_file_raises(self, tmp_path):
        cfg = SheetsConfig(
            service_account_file=str(tmp_path / "nope.json"),
        )
        with pytest.raises(RuntimeError, match="Service account file not found"):
            get_gspread_client(cfg)

    def test_missing_oauth_credentials_file_raises(self, tmp_path):
        cfg = SheetsConfig(credentials_file=str(tmp_path / "nope.json"))
        with pytest.raises(RuntimeError, match="credentials file not found"):
            get_gspread_client(cfg)
