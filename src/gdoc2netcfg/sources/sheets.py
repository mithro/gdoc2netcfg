"""Source: fetch CSV data from Google Sheets published URLs."""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass

#: Socket timeout (seconds) for one published-CSV request: connect and every
#: recv().  Without it a stalled TLS connection hangs the process forever —
#: monarto's cron fetch sat 6 days 16 h on an ESTABLISHED socket to Google
#: holding the fetch lock (2026-09-05), so no fetch ran at all.
SHEET_FETCH_TIMEOUT_SECONDS = 60.0


@dataclass
class SheetData:
    """Raw CSV data fetched from a Google Sheets published URL."""

    name: str
    csv_text: str


def fetch_sheet(
    name: str, url: str, *, timeout: float = SHEET_FETCH_TIMEOUT_SECONDS,
) -> SheetData:
    """Fetch CSV data from a Google Sheets published URL.

    Args:
        name: Human-readable sheet name (e.g. 'Network', 'IoT')
        url: Published CSV URL from Google Sheets
        timeout: Socket timeout in seconds for the connect and each read.
            Never None/0 — a fetch must not be able to hang.

    Returns:
        SheetData with the raw CSV text content.

    Raises:
        urllib.error.URLError: If the network request fails.
        TimeoutError: If the connect or a read stalls for *timeout* seconds.
        ValueError: If *timeout* is not a positive number.
    """
    if not timeout or timeout <= 0:
        raise ValueError(f"fetch_sheet timeout must be > 0, got {timeout!r}")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        csv_text = response.read().decode("utf-8")
    return SheetData(name=name, csv_text=csv_text)


def fetch_all_sheets(
    sheets: list[tuple[str, str]],
) -> list[SheetData]:
    """Fetch CSV data from all configured sheets.

    Args:
        sheets: List of (name, url) pairs.

    Returns:
        List of SheetData, one per sheet. Sheets that fail to fetch are
        skipped with a warning printed to stderr.
    """
    results = []
    for name, url in sheets:
        try:
            data = fetch_sheet(name, url)
            results.append(data)
        except Exception as e:
            import sys

            print(f"Warning: failed to fetch sheet {name!r}: {e}", file=sys.stderr)
    return results
