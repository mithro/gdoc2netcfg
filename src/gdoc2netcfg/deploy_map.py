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

#: The generators whose output a deploy installs — the Makefile's
#: DEPLOY_GENERATORS plus rsyslog (``make deploy-syslog`` generates that one
#: itself).  Keep the two in step: a generator missing here is a component
#: whose drift goes unnoticed.
DEPLOY_GENERATORS = (
    "dnsmasq_leaf",
    "pdns_internal",
    "pdns_external",
    "recursor_forward",
    "nginx",
    "known_hosts",
    "rsyslog",
)

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
    installed), ``"extra"`` (installed but no longer generated, which a real
    deploy would delete) or ``"empty"`` (the generator produced nothing where
    ``/etc`` has content — a broken run, never a pending deploy).  *path* is
    always the ``/etc`` path, because that is what an operator needs to look at.
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


@dataclass(frozen=True)
class LeafDir:
    """One per-net dnsmasq leaf: generated confs and their installed directory."""

    net: str
    src_dir: Path
    dst_dir: Path


@dataclass(frozen=True)
class PdnsPlan:
    """A pdns view's generated files, split the way the deploy treats them.

    The split is load-bearing: a changed bind conf needs ``systemctl restart
    pdns@<view>``, while changed zones only need ``bind-reload-now`` naming
    each zone.
    """

    view: str
    zone_pairs: list[tuple[Path, Path]]
    bind_pair: tuple[Path, Path] | None


def dnsmasq_leaf_dirs(out: Path, etc: Path = ETC) -> list[LeafDir]:
    """Generated per-net leaves that this host installs.

    A net with no ``/etc/dnsmasq.d/<net>/`` is omitted — that leaf does not run
    here, which is a site difference rather than a stale deploy.  See
    ``skipped_nets``.
    """
    leaves_root = out / "etc" / "dnsmasq.d"
    if not leaves_root.is_dir():
        return []
    leaves = []
    for net_dir in sorted(leaves_root.iterdir()):
        gen = net_dir / "generated"
        target = etc / "dnsmasq.d" / net_dir.name / "generated"
        if gen.is_dir() and target.parent.is_dir():
            leaves.append(LeafDir(net_dir.name, gen, target))
    return leaves


def skipped_nets(out: Path, *, etc: Path = ETC) -> list[str]:
    """Generated nets this host has no ``/etc/dnsmasq.d/<net>/`` for."""
    leaves_root = out / "etc" / "dnsmasq.d"
    if not leaves_root.is_dir():
        return []
    return [
        net_dir.name
        for net_dir in sorted(leaves_root.iterdir())
        if (net_dir / "generated").is_dir()
        and not (etc / "dnsmasq.d" / net_dir.name).is_dir()
    ]


def pdns_plan(out: Path, view: str, etc: Path = ETC) -> PdnsPlan:
    """Generated zones and bind conf for *view* ('internal' or 'external')."""
    out_pdns = out / "etc" / "powerdns"
    zones_dir = out_pdns / f"zones-{view}"
    bind_conf = out_pdns / f"bind-{view}.conf"
    zone_pairs = [
        (src, etc / "powerdns" / f"zones-{view}" / src.name)
        for src in (sorted(zones_dir.glob("*.zone")) if zones_dir.is_dir() else [])
    ]
    bind_pair = (
        (bind_conf, etc / "powerdns" / bind_conf.name) if bind_conf.exists() else None
    )
    return PdnsPlan(view, zone_pairs, bind_pair)


def recursor_pair(out: Path, etc: Path = ETC) -> tuple[Path, Path]:
    """The generated recursor forward-zones file and its installed path."""
    return (out / "etc" / "powerdns" / "forward-zones.yml",
            etc / "powerdns" / "forward-zones.yml")


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
    src_bytes = src.read_bytes()
    dst_bytes = dst.read_bytes()
    if src_bytes == dst_bytes:
        return []
    # A generator that produced nothing where /etc has content means the run
    # was broken (wrong cache directory, missing database), not that /etc is
    # stale.  Reporting it as drift would invite a deploy that installs the
    # emptiness — for known_hosts, wiping every host key.
    if not src_bytes:
        return [Drift(component, "empty", dst)]
    return [Drift(component, "changed", dst)]


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


def _dns_drift(out: Path, etc: Path) -> list[Drift]:
    """Drift for the dnsmasq leaves, both pdns views and the recursor."""
    drift: list[Drift] = []
    for leaf in dnsmasq_leaf_dirs(out, etc):
        generated = {p.name for p in leaf.src_dir.glob("*.conf")}
        for src in sorted(leaf.src_dir.glob("*.conf")):
            drift += _compare("dns", src, leaf.dst_dir / src.name)
        # deploy_leaves deletes generated confs that disappear from OUT.
        for installed in sorted(leaf.dst_dir.glob("*.conf")):
            if installed.name not in generated:
                drift.append(Drift("dns", "extra", installed))
    for view in ("internal", "external"):
        plan = pdns_plan(out, view, etc)
        # Zone files that are not generated are left in place on purpose (hand
        # extra_zones such as birds), so they are never drift.
        for src, dst in plan.zone_pairs:
            drift += _compare("dns", src, dst)
        if plan.bind_pair:
            drift += _compare("dns", *plan.bind_pair)
    drift += _compare("dns", *recursor_pair(out, etc))
    return drift


def find_drift(out: Path, *, etc: Path = ETC) -> list[Drift]:
    """Every difference between the generated tree *out* and installed *etc*."""
    drift: list[Drift] = _dns_drift(out, etc)
    for src, dst in nginx_pairs(out, etc):
        drift += _compare("nginx", src, dst)
    drift += _nginx_extras(out, etc)
    drift += _compare("known_hosts", *known_hosts_pair(out, etc))
    for src, dst in syslog_pairs(out, etc):
        drift += _compare("syslog", src, dst)
    return drift
