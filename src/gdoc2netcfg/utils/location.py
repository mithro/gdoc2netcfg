"""Location-path and natural-sort string helpers (pure, dependency-free)."""

from __future__ import annotations

import re

_LOCATION_SEP = " - "
_WS = re.compile(r"\s+")
_NONALNUM = re.compile(r"[^0-9a-z ]")
_DIGITS = re.compile(r"(\d+)")


def parse_location_path(cell: str) -> tuple[str, ...]:
    """Split a location cell into a trimmed hierarchy path (``A - B - C``)."""
    if not cell or not cell.strip():
        return ()
    return tuple(part.strip() for part in cell.split(_LOCATION_SEP) if part.strip())


def location_key(cell: str) -> str:
    """Normalized confusable key: casefold, collapse whitespace, drop punctuation.

    Two location cells that differ only by case/spacing/punctuation map to the
    same key — used ONLY to detect confusable duplicates, never to merge them.
    """
    parts = []
    for seg in parse_location_path(cell):
        seg = _NONALNUM.sub(" ", seg.casefold())
        parts.append(_WS.sub(" ", seg).strip().replace(" ", ""))
    return "/".join(p for p in parts if p)


def natural_sort_key(s: str) -> tuple:
    """Key for human/natural ordering: numeric runs compare as ints."""
    out: list[tuple[int, object]] = []
    for tok in _DIGITS.split(s):
        if tok.isdigit():
            out.append((0, int(tok)))
        elif tok:
            out.append((1, tok.casefold()))
    return tuple(out)
