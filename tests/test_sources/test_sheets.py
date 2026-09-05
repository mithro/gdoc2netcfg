"""Tests for sources.sheets.fetch_sheet — every request has a socket timeout."""

from __future__ import annotations

import io

import pytest

from gdoc2netcfg.sources import sheets
from gdoc2netcfg.sources.sheets import SHEET_FETCH_TIMEOUT_SECONDS, fetch_sheet


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _capture_urlopen(monkeypatch, body: bytes = b"Machine,MAC\n"):
    calls: list[tuple[str, dict]] = []

    def fake_urlopen(url, *args, **kwargs):
        calls.append((url, kwargs))
        return _FakeResponse(body)

    monkeypatch.setattr(sheets.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_default_timeout_is_passed_to_urlopen(monkeypatch):
    calls = _capture_urlopen(monkeypatch)
    data = fetch_sheet("network", "https://example.test/csv")
    assert data.csv_text == "Machine,MAC\n"
    assert calls == [("https://example.test/csv", {"timeout": SHEET_FETCH_TIMEOUT_SECONDS})]
    assert SHEET_FETCH_TIMEOUT_SECONDS == 60.0


def test_explicit_timeout_is_passed_through(monkeypatch):
    calls = _capture_urlopen(monkeypatch)
    fetch_sheet("network", "https://example.test/csv", timeout=7.5)
    assert calls[0][1] == {"timeout": 7.5}


@pytest.mark.parametrize("bad", [0, -1, None])
def test_non_positive_timeout_is_refused(monkeypatch, bad):
    """A fetch must never be able to hang: no timeout is not an option."""
    calls = _capture_urlopen(monkeypatch)
    with pytest.raises(ValueError, match="timeout"):
        fetch_sheet("network", "https://example.test/csv", timeout=bad)
    assert calls == []


def test_stalled_request_raises_instead_of_hanging(monkeypatch):
    def stalled(url, *args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(sheets.urllib.request, "urlopen", stalled)
    with pytest.raises(TimeoutError):
        fetch_sheet("network", "https://example.test/csv", timeout=1)
