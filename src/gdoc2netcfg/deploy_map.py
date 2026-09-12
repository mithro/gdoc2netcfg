"""Where each generated file lands under /etc, and what currently differs.

This module is the single source of truth for the generated-to-installed path
mapping.  ``scripts/deploy_dns.py`` installs from it and ``gdoc2netcfg
deploy-check`` compares against it, so a deploy and a staleness check can
never disagree about where a file belongs.

A deploy is a separate privileged step from ``generate``: nothing in cron
installs anything.  ``find_drift`` answers "is /etc what the generators would
produce right now?" so that a stale deploy reports itself instead of
surfacing later as phantom device faults (2026-09-12: a seven-day-old deploy
made the nightly Tasmota scan report two IoT boards as being at the wrong
address, when in truth their reservations had never been installed).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ETC = Path("/etc")

#: Installed by the nginx deploy itself (and chowned to www-data), never
#: generated — comparing it would report drift forever.
NGINX_DEPLOY_ARTIFACTS = frozenset({"status.txt"})


@dataclass(frozen=True)
class Drift:
    """One generated-vs-installed difference.

    *kind* is ``"changed"`` (installed copy differs), ``"missing"`` (never
    installed) or ``"extra"`` (installed but no longer generated, which a real
    deploy would delete).  *path* is always the ``/etc`` path, because that is
    what an operator needs to look at.
    """

    component: str
    kind: str
    path: Path


def changed(src: Path, dst: Path) -> bool:
    """True if *dst* is absent or its bytes differ from *src*."""
    return not dst.exists() or src.read_bytes() != dst.read_bytes()


def known_hosts_pair(out: Path, etc: Path = ETC) -> tuple[Path, Path]:
    """The generated known_hosts file and where ``make deploy-known-hosts`` puts it."""
    return out / "known_hosts", etc / "ssh" / "ssh_known_hosts"


def _compare(component: str, src: Path, dst: Path) -> list[Drift]:
    """Drift for a single generated file, or [] when it is in sync."""
    if not src.exists():
        return []
    if not dst.exists():
        return [Drift(component, "missing", dst)]
    if src.read_bytes() != dst.read_bytes():
        return [Drift(component, "changed", dst)]
    return []


def find_drift(out: Path, *, etc: Path = ETC) -> list[Drift]:
    """Every difference between the generated tree *out* and installed *etc*."""
    return _compare("known_hosts", *known_hosts_pair(out, etc))
