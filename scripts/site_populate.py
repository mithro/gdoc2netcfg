"""One-off: propose a Site value for every device row from live evidence.

THROWAWAY migration tool (committed for the record, removed after the
migration lands). Read-only until --apply; --apply writes Site cells via
explicit A1 ranges only after Tim approves the proposal. See
docs/superpowers/specs/2026-10-08-site-column-mandatory-design.md.

The pure classifier `classify_site` is unit-tested; the evidence-gathering
and proposal/output I/O in `main()` is operational (reads live DBs + sheet)
and is exercised during the rollout, not in CI.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SiteEvidence:
    """What we know about where one device row actually lives."""

    machine: str
    current_site: str
    ip: str
    seen_welland: bool
    seen_monarto: bool
    on_roam_vlan: bool


@dataclass
class SiteProposal:
    """A suggested Site value, never a silent write.

    `suggested` is "welland" | "monarto" | "roam" | None (UNKNOWN).
    `confidence` is "high" | "low" | "unknown".
    """

    suggested: str | None
    confidence: str
    flags: list[str] = field(default_factory=list)


def _is_site_literal(ip: str) -> bool:
    """True for a site-specific private literal (10.1.* / 10.2.*).

    Such an address only works at one site, so a roam device must not carry
    one (it needs the 10.X placeholder or a non-site-specific address).
    """
    parts = ip.split(".")
    return len(parts) == 4 and parts[0] == "10" and parts[1] in ("1", "2")


def classify_site(ev: SiteEvidence) -> SiteProposal:
    """Propose a Site from live evidence. Never guesses: absent evidence and
    no prior value -> UNKNOWN for Tim to decide."""
    flags: list[str] = []
    if ev.on_roam_vlan or (ev.seen_welland and ev.seen_monarto):
        if _is_site_literal(ev.ip):
            flags.append("roam but carries a site-literal IP — make it 10.X "
                         "or place single-site")
        return SiteProposal("roam", "high", flags)
    if ev.seen_welland:
        return SiteProposal("welland", "high", flags)
    if ev.seen_monarto:
        return SiteProposal("monarto", "high", flags)
    if ev.current_site:
        # No live evidence: keep what the sheet already says, low confidence.
        return SiteProposal(ev.current_site.lower(), "low", flags)
    return SiteProposal(None, "unknown", flags)


# ---------------------------------------------------------------------------
# Operational I/O (NOT unit-tested; validated interactively during the rollout
# against live DBs + the sheet — see the plan's rollout section). The risky
# decision logic above is tested; everything below is glue.
# ---------------------------------------------------------------------------


def _reachable_hostnames(db) -> set[str]:
    """Short machine names that answered a ping in the latest reachability scan.

    load_latest_reachability() returns
    {hostname: {"interfaces": [[{ip, transmitted, received, rtt_avg_ms}]]}}.
    A host is "seen" if any interface received > 0. The key is a full hostname
    (e.g. au-plug-1.iot.welland.mithis.com); we key evidence on its first
    label (the sheet Machine name).
    """
    data = db.load_latest_reachability() or {}
    seen: set[str] = set()
    for hostname, doc in data.items():
        up = any(
            entry.get("received", 0) > 0
            for iface in doc.get("interfaces", [])
            for entry in iface
        )
        if up:
            seen.add(hostname.split(".")[0].lower())
    return seen


def _roam_third_octets(site, roam_vlan_name: str) -> frozenset[int]:
    for vlan in site.vlans.values():
        if vlan.name == roam_vlan_name:
            return frozenset(vlan.third_octets)
    return frozenset()


def _on_roam_vlan(ip: str, roam_octets: frozenset[int]) -> bool:
    parts = ip.split(".")
    if len(parts) != 4 or parts[0] != "10":
        return False
    try:
        return int(parts[2]) in roam_octets
    except ValueError:
        return False


def _device_rows(csv_path):
    """Yield (row_number, machine, ip, current_site) for real device rows.

    Finds the header row (the first containing a 'site' cell) and the
    machine/ip/site columns case-insensitively; skips rows with neither a
    machine name nor an IP (spacers/section labels).
    """
    import csv

    with open(csv_path, newline="") as f:
        rows = list(csv.reader(f))
    hdr_idx = next(
        (i for i, r in enumerate(rows)
         if any(c.strip().lower() == "site" for c in r)), None)
    if hdr_idx is None:
        return
    lh = [c.strip().lower() for c in rows[hdr_idx]]

    def col(*names):
        return next((lh.index(n) for n in names if n in lh), None)

    si, mi, ii = col("site"), col("machine", "machine name", "name"), \
        col("ip", "ip address", "ipv4")

    def cell(r, idx):
        return r[idx].strip() if idx is not None and idx < len(r) else ""

    for n, r in enumerate(rows[hdr_idx + 1:], start=hdr_idx + 2):
        machine, ip, current = cell(r, mi), cell(r, ii), cell(r, si)
        if not machine and not ip:
            continue
        yield n, machine, ip, current


def main(argv: list[str] | None = None) -> int:
    import argparse

    from gdoc2netcfg.config import load_config
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=None,
                    help="path to gdoc2netcfg.toml (default: discovered)")
    ap.add_argument("--monarto-db", default=None,
                    help="path to a copy of monarto's discovery.db for "
                         "cross-site reachability evidence")
    ap.add_argument("--roam-vlan", default="roam",
                    help="VLAN name whose members are roaming devices")
    ap.add_argument("--apply", action="store_true",
                    help="write the approved Site values to the sheet")
    args = ap.parse_args(argv)

    if args.apply:
        # The sheet writer (via utils/gsheets.py, explicit A1 ranges) is wired
        # at rollout time against the live sheet, after Tim approves the
        # proposal — it is a prod write and must not run from a blind guess.
        raise SystemExit(
            "--apply is wired during the Tim-gated rollout; run without "
            "--apply to produce the proposal for review first.")

    config = load_config(args.config)
    roam_octets = _roam_third_octets(config.site, args.roam_vlan)
    with DiscoveryDB(config.cache.discovery_db_path) as wdb:
        welland_up = _reachable_hostnames(wdb)
    monarto_up: set[str] = set()
    if args.monarto_db:
        with DiscoveryDB(args.monarto_db) as mdb:
            monarto_up = _reachable_hostnames(mdb)

    counts: dict[str, int] = {}
    unknown: list[str] = []
    flagged: list[str] = []
    cache = config.cache.directory
    print(f"{'sheet:row':<14} {'machine':<22} {'now':<9} "
          f"{'->':<9} {'conf':<7} flags")
    for sheet in ("network", "iot", "wifi"):
        path = cache / f"{sheet}.csv"
        if not path.exists():
            continue
        for row_no, machine, ip, current in _device_rows(path):
            key = machine.lower()
            ev = SiteEvidence(
                machine=machine, current_site=current, ip=ip,
                seen_welland=key in welland_up,
                seen_monarto=key in monarto_up,
                on_roam_vlan=_on_roam_vlan(ip, roam_octets),
            )
            p = classify_site(ev)
            label = p.suggested or "UNKNOWN"
            counts[label] = counts.get(label, 0) + 1
            if p.suggested is None:
                unknown.append(f"{sheet}:{row_no} {machine} ({ip})")
            if p.flags:
                flagged.append(f"{sheet}:{row_no} {machine}: {'; '.join(p.flags)}")
            print(f"{sheet}:{row_no:<9} {machine:<22} {current or '-':<9} "
                  f"{label:<9} {p.confidence:<7} {'; '.join(p.flags)}")

    print("\nsummary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if unknown:
        print(f"\nUNKNOWN — need Tim's decision ({len(unknown)}):")
        for u in unknown:
            print(f"  {u}")
    if flagged:
        print(f"\nflagged ({len(flagged)}):")
        for fl in flagged:
            print(f"  {fl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
