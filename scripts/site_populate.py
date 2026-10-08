"""One-off: propose a Site value for every device row from live evidence.

THROWAWAY migration tool (committed for the record, removed after the
migration lands). Read-only until --apply; --apply writes Site cells via
explicit A1 ranges only after Tim approves the proposal. See
docs/superpowers/specs/2026-10-08-site-column-mandatory-design.md.

The pure classifier `classify_site` and the pure parsers (`_roam_octets_from_csv`,
`_norm_mac`) are unit-tested; the evidence-gathering + proposal/output I/O in
`main()` is operational (reads live DBs + the sheet CSVs) and is exercised
during the rollout, not in CI.

Runs against a --data directory of the cached sheet CSVs + vlan_allocations.csv
plus the two sites' discovery.db copies, so the proposal can be iterated
locally without deploying; only --apply touches the live sheet (on prod, root).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


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


def _base_machine(machine: str) -> str:
    """Strip a trailing ' - NN' aggregate-row suffix to the base machine name.

    Each host block's anchor row carries ``<machine> - <n>`` (the sheet's
    Aggregate convention) and has no IP/MAC; its interface rows carry the bare
    ``<machine>``. Normalising lets the anchor resolve like its interfaces.
    """
    return re.sub(r"\s+-\s+\d+$", "", machine).strip()


def _residual_site(machine: str) -> str | None:
    """Tim's residual placement rules for rows with no live signal.

    welland (2026-10-08, batch 1): backbone (sw-bb-*) + their ports, m4300 +
    poe-micro switches, and the named build-farm hosts (power9*, desktop,
    *nvmeof, hifive-unmatched*, dell-c410x*).
    welland (batch 2): all remaining netgear switches (sw-netgear-*), AV
    (samsung-tv/yamaha-receiver/bluray-player), power (hp-power/ups-*/
    tplink-powerline), fritz-box-*, and gpu*.
    welland (batch 3, "land it, I'll inspect"): the remaining rows with no
    live signal at EITHER site (both discovery.dbs checked) — the welland
    build-farm/compute cluster (rpi5*, opi1pc-*, moboco, qnap, wlan0, ty-wr,
    hls-fpga-*, ten11/12/70/97, enx*, rpi-sdr-*, sdr-mqtt) and welland
    home-automation IoT (light*, switch-*, bathroom*, kitchen*, bedroom,
    rack-light, opener*, spray, neocharge*, geekmagic*, bridge-433-*,
    mac-mini). Placed welland for Tim to correct on the sheet.
    roam: carl's machines; all pixel phones; sager-chromeosflex (laptop).
    kindle-<site>-dash encodes its site in the name.
    Everything else stays undetermined (returns None).
    """
    m = machine.lower()
    if m.startswith("kindle-welland"):
        return "welland"
    if m.startswith("kindle-monarto"):
        return "monarto"
    if (m.startswith("sw-bb-") or m.startswith("ports.sw-bb-")
            or m.startswith("sw-netgear-")
            or m.startswith("power9") or m == "desktop" or "nvmeof" in m
            or m.startswith("hifive-unmatched") or m.startswith("dell-c410x")
            or m in ("samsung-tv", "yamaha-receiver", "bluray-player")
            or m in ("hp-power", "ups-rack", "ups-test", "tplink-powerline")
            or m.startswith("fritz-box") or m.startswith("gpu")
            # batch 3: welland build-farm / compute
            or m.startswith("rpi5") or m.startswith("opi1pc")
            or m in ("moboco", "qnap", "wlan0", "ty-wr", "mac-mini")
            or m.startswith("hls-fpga") or m in ("ten11", "ten12", "ten70",
                                                 "ten97")
            or m.startswith("enx") or m.startswith("rpi-sdr")
            or m == "sdr-mqtt"
            # batch 3: welland home-automation IoT
            or m.startswith("light") or m.startswith("switch-")
            or m.startswith("bathroom") or m.startswith("kitchen")
            or m in ("bedroom", "rack-light", "spray")
            or m.startswith("opener") or m.startswith("neocharge")
            or m.startswith("geekmagic") or m.startswith("bridge-433")):
        return "welland"
    if (m.startswith("carl") or m.startswith("pixel")
            or m.startswith("sager")):
        return "roam"
    return None


# ---------------------------------------------------------------------------
# Pure parsers (unit-tested)
# ---------------------------------------------------------------------------


def _norm_mac(s: str | None) -> str | None:
    """Normalise a MAC to uppercase colon form, or None if it isn't one.

    Accepts colon/dash/dot/bare hex; `none`/blank/garbage -> None. The FDB
    stores uppercase-colon MACs, so both sides compare equal after this.
    """
    hexchars = re.sub(r"[^0-9A-Fa-f]", "", s or "")
    if len(hexchars) != 12:
        return None
    h = hexchars.upper()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _roam_octets_from_csv(vlan_csv: Path, roam_name: str) -> set[int]:
    """Third octets owned by the roam VLAN, read from the VLAN Allocations CSV.

    A row is e.g. ``20,roam,10.X.20.X,...`` — the Subnet column's third octet
    (20) is the roam third octet. Independent of site_octet (octet 2).
    """
    import csv

    with open(vlan_csv, newline="") as f:
        rows = list(csv.reader(f))
    hdr_idx = next(
        (i for i, r in enumerate(rows)
         if any(c.strip().lower() in ("vlan name", "name") for c in r)), None)
    if hdr_idx is None:
        return set()
    lh = [c.strip().lower() for c in rows[hdr_idx]]

    def col(*names):
        return next((lh.index(n) for n in names if n in lh), None)

    name_col = col("vlan name", "name")
    subnet_col = col("subnet", "network", "ip range")
    if name_col is None or subnet_col is None:
        return set()
    octets: set[int] = set()
    for r in rows[hdr_idx + 1:]:
        if name_col >= len(r) or subnet_col >= len(r):
            continue
        if r[name_col].strip().lower() != roam_name.lower():
            continue
        parts = r[subnet_col].strip().split(".")
        if len(parts) == 4 and parts[2].isdigit():
            octets.add(int(parts[2]))
    return octets


def _on_roam_vlan(ip: str, roam_octets: set[int]) -> bool:
    parts = ip.split(".")
    if len(parts) != 4 or parts[0] != "10" or not parts[2].isdigit():
        return False
    return int(parts[2]) in roam_octets


# ---------------------------------------------------------------------------
# Operational I/O (NOT unit-tested; validated interactively during the rollout
# against live DBs + the sheet). The decision logic above is tested.
# ---------------------------------------------------------------------------


def _open_readonly(path):
    """Open a discovery.db read-only (mode=ro).

    The proposal only reads: read_only keeps a non-root run working against
    the root-owned prod DB and never takes write locks on the live DB the
    reachability daemon is writing.
    """
    from gdoc2netcfg.storage.discovery_db import DiscoveryDB

    return DiscoveryDB(Path(path), read_only=True)


def _reachable_hostnames(db) -> set[str]:
    """Short machine names (first hostname label) that answered a ping in the
    latest reachability scan (any interface received > 0)."""
    data = db.load_latest_reachability() or {}
    seen: set[str] = set()
    for hostname, doc in data.items():
        up = any(
            (entry.get("received") or 0) > 0
            for iface in doc.get("interfaces", [])
            for entry in iface
        )
        if up:
            seen.add(hostname.split(".")[0].lower())
    return seen


def _fdb_macs(db) -> set[str]:
    """Every normalised MAC a switch at this site has learned (bridge FDB).

    A device whose MAC appears here is physically present on that site's
    network even if it didn't answer a ping.
    """
    bridge = db.load_latest_bridge() or {}
    macs: set[str] = set()
    for doc in bridge.values():
        for row in doc.get("mac_table", []):
            m = _norm_mac(row[0] if row else None)
            if m:
                macs.add(m)
    return macs


def _device_rows(csv_path):
    """Yield (row_number, machine, ip, current_site, mac) for real device rows.

    Finds the header row (first containing a 'site' cell) and the
    machine/ip/site/mac columns case-insensitively; skips rows with neither a
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

    si = col("site")
    mi = col("machine", "machine name", "name")
    ii = col("ip", "ip address", "ipv4")
    mac_i = col("mac", "mac address")

    def cell(r, idx):
        return r[idx].strip() if idx is not None and idx < len(r) else ""

    for n, r in enumerate(rows[hdr_idx + 1:], start=hdr_idx + 2):
        machine, ip = cell(r, mi), cell(r, ii)
        # Match the Phase-2 validator: only rows with a machine name become
        # hosts and need a Site; blank-machine rows (spacers, IP-only stubs)
        # are skipped there, so they don't belong in the proposal either.
        if not machine:
            continue
        yield n, machine, ip, cell(r, si), cell(r, mac_i)


# Worksheet gids in the EDIT doc (key 1fFm2...); cross-checked against the pub
# CSV gids and scripts/add_aggregate_column.py (network == 1476589425).
_SHEET_GID = {"network": 1476589425, "iot": 1695016218, "wifi": 1724224613}
_VALID_SITES = ("welland", "monarto", "roam", "special")


def _site_col_index(csv_path) -> int | None:
    """0-based index of the Site column in a sheet CSV (header-detected)."""
    import csv

    with open(csv_path, newline="") as f:
        for row in csv.reader(f):
            for i, c in enumerate(row):
                if c.strip().lower() == "site":
                    return i
    return None


def _do_writes(writes, spreadsheet_url, sheets_config) -> None:
    """Write Site cells to the live sheet, verifying each tab's Site column
    first (aborts loudly on gid/layout drift). writes: list of dicts with
    sheet/gid/row/col1/value."""
    import gspread.utils

    from gdoc2netcfg.utils.gsheets import get_gspread_client

    client = get_gspread_client(sheets_config)
    sh = client.open_by_url(spreadsheet_url)
    by_tab: dict[tuple, list] = {}
    for w in writes:
        by_tab.setdefault((w["sheet"], w["gid"], w["col1"]), []).append(w)
    for (sheet, gid, col1), ws_writes in by_tab.items():
        ws = sh.get_worksheet_by_id(gid)
        head = ws.get("A1:BZ5")
        hdr = next((r for r in head
                    if any(c.strip().lower() == "site" for c in r)), None)
        if hdr is None:
            raise SystemExit(f"{sheet} (gid {gid}): no Site header found — abort")
        live_col = [c.strip().lower() for c in hdr].index("site") + 1
        if live_col != col1:
            raise SystemExit(
                f"{sheet} (gid {gid}): Site is live column {live_col} but the "
                f"CSV put it at {col1} — sheet layout drifted, aborting.")
        batch = [{"range": gspread.utils.rowcol_to_a1(w["row"], col1),
                  "values": [[w["value"]]]} for w in ws_writes]
        ws.batch_update(batch, value_input_option="RAW")
        print(f"  {sheet}: wrote {len(batch)} Site cells")


def main(argv: list[str] | None = None) -> int:
    import argparse

    import gspread.utils

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", default=".cache",
                    help="dir with the sheet CSVs + vlan_allocations.csv")
    ap.add_argument("--welland-db", default=None,
                    help="welland discovery.db (default: <data>/discovery.db)")
    ap.add_argument("--monarto-db", default=None,
                    help="a read-only copy of monarto's discovery.db")
    ap.add_argument("--roam-vlan", default="roam",
                    help="VLAN name whose subnet marks roaming devices")
    ap.add_argument("--dry-run", action="store_true",
                    help="print exactly which Site cells --apply would write")
    ap.add_argument("--apply", action="store_true",
                    help="write determined Site values to the live sheet (prod, "
                         "service account); only blank cells + case fixes")
    args = ap.parse_args(argv)

    data = Path(args.data)
    roam_octets = _roam_octets_from_csv(data / "vlan_allocations.csv", args.roam_vlan)
    with _open_readonly(args.welland_db or (data / "discovery.db")) as wdb:
        welland_up, welland_fdb = _reachable_hostnames(wdb), _fdb_macs(wdb)
    monarto_up: set[str] = set()
    monarto_fdb: set[str] = set()
    if args.monarto_db:
        with _open_readonly(args.monarto_db) as mdb:
            monarto_up, monarto_fdb = _reachable_hostnames(mdb), _fdb_macs(mdb)

    verbose = not (args.apply or args.dry_run)
    counts: dict[str, int] = {}
    unknown: list[str] = []
    flagged: list[str] = []
    writes: list[dict] = []
    if verbose:
        print(f"roam third-octets: {sorted(roam_octets)}; welland up="
              f"{len(welland_up)} fdb={len(welland_fdb)}; monarto up="
              f"{len(monarto_up)} fdb={len(monarto_fdb)}")
        print(f"\n{'sheet:row':<12} {'machine':<24} {'now':<9} {'->':<9} "
              f"{'conf':<6} evidence")
    for sheet in ("network", "iot", "wifi"):
        path = data / f"{sheet}.csv"
        if not path.exists():
            continue
        site_col0 = _site_col_index(path)
        for row_no, machine, ip, current, mac in _device_rows(path):
            base = _base_machine(machine)
            key = base.lower()
            nmac = _norm_mac(mac)
            # A site-literal IP is authoritative and single-site: it overrides
            # reachability/FDB, which collide for same-named per-site infra
            # (welland and monarto each have their own ten64/wisp/ha, both "up").
            if ip.startswith("10.1."):
                seen_w, seen_m = True, False
            elif ip.startswith("10.2."):
                seen_w, seen_m = False, True
            else:
                seen_w = key in welland_up or (nmac is not None and nmac in welland_fdb)
                seen_m = key in monarto_up or (nmac is not None and nmac in monarto_fdb)
            ev = SiteEvidence(machine, current, ip, seen_w, seen_m,
                              _on_roam_vlan(ip, roam_octets))
            p = classify_site(ev)
            if p.suggested is None:
                rsite = _residual_site(base)
                if rsite is not None:
                    p = SiteProposal(rsite, "rule", [])
            label = p.suggested or "UNKNOWN"
            counts[label] = counts.get(label, 0) + 1
            if p.suggested is None:
                unknown.append(f"{sheet}:{row_no} {machine} ({ip})")
            if p.flags:
                flagged.append(f"{sheet}:{row_no} {machine}: {'; '.join(p.flags)}")

            # Write-set: fill a BLANK cell with a determined value, and normalise
            # a mis-cased existing value (Welland -> welland). Never overwrite a
            # correctly-cased existing Site.
            desired = None
            if not current and p.suggested is not None:
                desired = p.suggested
            elif (current and current != current.lower()
                  and current.lower() in _VALID_SITES):
                desired = current.lower()
            # The wifi tab's Site column is vertically merged per host block
            # (wifi-sheet-format.py), so only a block's ANCHOR row exports a
            # value; covered rows read blank on the CSV and the parser's
            # carry-forward inherits the anchor's Site at pipeline time. Every
            # wifi anchor already carries a Site, so a "blank" wifi cell here is
            # always a covered row — writing it targets a merged cell (futile)
            # and could stamp a value that disagrees with its anchor. Never
            # write wifi; it is populated in-pipeline, not on the sheet.
            if (desired and desired != current and site_col0 is not None
                    and sheet != "wifi"):
                writes.append({"sheet": sheet, "gid": _SHEET_GID[sheet],
                               "row": row_no, "col1": site_col0 + 1,
                               "value": desired, "current": current})
            if verbose:
                why = ",".join(
                    w for w, on in (("roam-vlan", ev.on_roam_vlan),
                                    ("welland", seen_w), ("monarto", seen_m)) if on
                ) or ("sheet=" + current if current else "none")
                print(f"{sheet}:{row_no:<7} {machine:<24} {current or '-':<9} "
                      f"{label:<9} {p.confidence:<6} {why}")

    print("\nsummary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    wcount: dict[str, int] = {}
    for w in writes:
        wcount[w["sheet"]] = wcount.get(w["sheet"], 0) + 1
    print(f"write-set: {len(writes)} cells ("
          + ", ".join(f"{k}={v}" for k, v in sorted(wcount.items())) + ")")
    if verbose and unknown:
        print(f"\nUNKNOWN — need Tim's decision ({len(unknown)}):")
        for u in unknown:
            print(f"  {u}")
    if verbose and flagged:
        print(f"\nflagged ({len(flagged)}):")
        for fl in flagged:
            print(f"  {fl}")

    if args.dry_run:
        print(f"\n--dry-run: {len(writes)} cells would be written:")
        for w in writes:
            a1 = gspread.utils.rowcol_to_a1(w["row"], w["col1"])
            print(f"  {w['sheet']} {a1}: {w['current'] or '(blank)'} -> {w['value']}")
    if args.apply:
        if not writes:
            print("nothing to write.")
            return 0
        from gdoc2netcfg.config import load_config
        config = load_config()
        if not config.spreadsheet_url:
            raise SystemExit("spreadsheet_url not configured in [sheets]")
        print(f"\nwriting {len(writes)} Site cells to the live sheet...")
        _do_writes(writes, config.spreadsheet_url, config.sheets_config)
        print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
