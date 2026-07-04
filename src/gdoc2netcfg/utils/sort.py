"""Shared sort-key helpers."""

from __future__ import annotations

import re


def natural_sort_key(name: str) -> list:
    """Sort key for names with embedded numbers (gi2 before gi10)."""
    return [
        int(part) if part.isdigit() else part.lower()
        for part in re.split(r"(\d+)", name)
    ]
