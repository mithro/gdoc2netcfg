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

#: The subtrees `make deploy-nginx` wipes before copying.  Only these can hold
#: an "extra" file: anything else under the deploy root is never removed, so a
#: leftover there is not something a deploy would clean up.
NGINX_WIPED_SUBTREES = ("sites-available", "scripts", "conf.d", "stream.d")


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


def syslog_pairs(out: Path, etc: Path = ETC) -> list[tuple[Path, Path]]:
    """The two files `make deploy-syslog` installs."""
    return [
        (out / "etc" / "rsyslog.d" / "remote-logs.conf",
         etc / "rsyslog.d" / "remote-logs.conf"),
        (out / "etc" / "logrotate.d" / "remote-logs",
         etc / "logrotate.d" / "remote-logs"),
    ]


def nginx_root(etc: Path = ETC) -> Path:
    """Where `make deploy-nginx` copies the generated tree."""
    return etc / "nginx" / "gdoc2netcfg"


def nginx_pairs(out: Path, etc: Path = ETC) -> list[tuple[Path, Path]]:
    """Every generated nginx file and where the deploy's ``cp -r`` puts it."""
    src_root = out / "nginx"
    if not src_root.is_dir():
        return []
    dst_root = nginx_root(etc)
    return [
        (src, dst_root / src.relative_to(src_root))
        for src in sorted(src_root.rglob("*"))
        if src.is_file()
    ]


def _compare(component: str, src: Path, dst: Path) -> list[Drift]:
    """Drift for a single generated file, or [] when it is in sync."""
    if not src.exists():
        return []
    if not dst.exists():
        return [Drift(component, "missing", dst)]
    if src.read_bytes() != dst.read_bytes():
        return [Drift(component, "changed", dst)]
    return []


def _nginx_extras(out: Path, etc: Path) -> list[Drift]:
    """Installed nginx files in a wiped subtree that are no longer generated."""
    src_root = out / "nginx"
    dst_root = nginx_root(etc)
    if not src_root.is_dir() or not dst_root.is_dir():
        return []
    extras: list[Drift] = []
    for subtree in NGINX_WIPED_SUBTREES:
        installed_root = dst_root / subtree
        if not installed_root.is_dir():
            continue
        for installed in sorted(installed_root.rglob("*")):
            if not installed.is_file() or installed.name in NGINX_DEPLOY_ARTIFACTS:
                continue
            if not (src_root / installed.relative_to(dst_root)).exists():
                extras.append(Drift("nginx", "extra", installed))
    return extras


def find_drift(out: Path, *, etc: Path = ETC) -> list[Drift]:
    """Every difference between the generated tree *out* and installed *etc*."""
    drift: list[Drift] = []
    for src, dst in nginx_pairs(out, etc):
        drift += _compare("nginx", src, dst)
    drift += _nginx_extras(out, etc)
    drift += _compare("known_hosts", *known_hosts_pair(out, etc))
    for src, dst in syslog_pairs(out, etc):
        drift += _compare("syslog", src, dst)
    return drift
