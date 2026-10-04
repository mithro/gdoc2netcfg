"""Location-path and natural-sort string helpers (pure, dependency-free)."""

from __future__ import annotations

import re

_LOCATION_SEP = " - "
_NONALNUM = re.compile(r"[^0-9a-z]+")
_DIGITS = re.compile(r"(\d+)")


def parse_location_path(cell: str) -> tuple[str, ...]:
    """Split a location cell into a trimmed hierarchy path (``A - B - C``)."""
    if not cell or not cell.strip():
        return ()
    return tuple(part.strip() for part in cell.split(_LOCATION_SEP) if part.strip())


def location_key(cell: str) -> str:
    """Normalized confusable key: casefold, drop every non-alphanumeric char.

    Separator/space/punctuation-insensitive, so ``Back Shed - Soundproof Rack``
    and ``Back Shed-Soundproof Rack`` (a missing space around the ` - `
    separator) map to the same key. Used ONLY to detect confusable duplicates,
    never to merge them — the fix makes the raw values identical.
    """
    return _NONALNUM.sub("", cell.casefold())


def natural_sort_key(s: str) -> tuple:
    """Key for human/natural ordering: numeric runs compare as ints."""
    out: list[tuple[int, object]] = []
    for tok in _DIGITS.split(s):
        if tok.isdigit():
            out.append((0, int(tok)))
        elif tok:
            out.append((1, tok.casefold()))
    return tuple(out)
