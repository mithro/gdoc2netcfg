"""Shared parsing for the spreadsheet ``Controls`` column and switch port
descriptions.

Extracted from ``supplements/tasmota.py`` and the reachability dashboard so
the power-topology engine and those consumers agree on how a ``Controls``
cell and an interface-prefixed port description are split.
"""

from __future__ import annotations

import re

# Interface-name prefixes seen in switch port descriptions (ifAlias), e.g.
# "eth0.rpi5-pmod", "1/0/49.sw-cisco-shed". Mirrors the dashboard regex.
_IFACE_PREFIX_RE = re.compile(
    r"^(?:"
    r"eth\d+|eth-\w+"
    r"|eno\d+|enp\w+|en\d+"
    r"|lan\d*"
    r"|(?:10|25|40|100)g\d+"
    r"|oob\d+"
    r"|gi\d+|te\d+|xe\d+|fo\d+"
    r"|lag\d*"
    r"|\d+(?:/[\w]+)+"
    r")\."
)


def parse_controls_cell(value: str) -> tuple[str, ...]:
    """Split a ``Controls`` cell into target names (comma/newline separated)."""
    return tuple(c.strip() for c in re.split(r"[,\r\n]", value or "") if c.strip())


def strip_interface_prefix(desc: str) -> tuple[str, str]:
    """Split a port description into ``(interface, rest)``.

    ``"eth0.rpi5-pmod"`` -> ``("eth0", "rpi5-pmod")``;
    ``"desktop"`` -> ``("", "desktop")``.
    """
    m = _IFACE_PREFIX_RE.match(desc)
    if not m:
        return ("", desc)
    return (desc[: m.end() - 1], desc[m.end():])
