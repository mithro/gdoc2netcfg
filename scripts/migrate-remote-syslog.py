#!/usr/bin/env python3
"""One-off migration to the per-net remote syslog layout (run per site).

Moves the legacy class directories to their net-named successors and
removes the superseded hand-written configs:

  /var/log/tasmota/*  -> /var/log/iot/      (Tasmota devices live on iot)
  /var/log/network/*  -> /var/log/net/      (switches/wisp -> the net class)
  /etc/rsyslog.d/tasmota.conf              (replaced by remote-logs.conf)
  /etc/rsyslog.d/z-network-switches.conf   (replaced by remote-logs.conf)
  /etc/logrotate.d/tasmota                 (replaced by remote-logs)
  /etc/logrotate.d/* mentioning /var/log/network/  (hand-deployed strays)

Dry-run by default; pass --apply to act. Idempotent: absent sources are
reported and skipped. Refuses (exit 1, nothing moved) if any destination
file already exists. If rsyslog writes a fresh file into a source dir
between the scan and the rmdir, the script aborts loudly on the non-empty
directory — safe to just re-run. Does NOT touch rsyslog or install new
configs — run
`sudo make deploy-syslog` immediately after (documented sequence:
migrate --apply, then deploy).

Usage:
    sudo uv run scripts/migrate-remote-syslog.py           # dry run
    sudo uv run scripts/migrate-remote-syslog.py --apply
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

MOVES = [("tasmota", "iot"), ("network", "net")]
REMOVE_CONFIGS = [
    "rsyslog.d/tasmota.conf",
    "rsyslog.d/z-network-switches.conf",
    "logrotate.d/tasmota",
]


def _planned_moves(log_root: Path) -> list[tuple[Path, Path]]:
    moves: list[tuple[Path, Path]] = []
    for old, new in MOVES:
        src_dir = log_root / old
        if not src_dir.is_dir():
            print(f"skip: {src_dir} absent (already migrated?)")
            continue
        for src in sorted(src_dir.iterdir()):
            moves.append((src, log_root / new / src.name))
    return moves


def _stray_network_logrotate(etc_root: Path) -> list[Path]:
    strays = []
    logrotate_d = etc_root / "logrotate.d"
    if logrotate_d.is_dir():
        for f in sorted(logrotate_d.iterdir()):
            if f.name == "tasmota" or not f.is_file():
                continue
            if "/var/log/network/" in f.read_text(errors="replace"):
                strays.append(f)
    return strays


def migrate(log_root: Path, etc_root: Path, *, apply: bool) -> None:
    moves = _planned_moves(log_root)
    conflicts = [dst for _, dst in moves if dst.exists()]
    if conflicts:
        print("REFUSING: destination file(s) already exist:", file=sys.stderr)
        for c in conflicts:
            print(f"  {c}", file=sys.stderr)
        raise SystemExit(1)

    removals = [
        p for rel in REMOVE_CONFIGS if (p := etc_root / rel).exists()
    ] + _stray_network_logrotate(etc_root)

    mode = "apply" if apply else "DRY RUN"
    print(f"[{mode}] {len(moves)} file move(s), {len(removals)} config removal(s)")
    for src, dst in moves:
        print(f"  move {src} -> {dst}")
        if apply:
            dst.parent.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
    for old, _ in MOVES:
        d = log_root / old
        if not d.is_dir():
            continue
        if apply:
            d.rmdir()  # fails loud if anything unexpected remains
            print(f"  removed empty {d}")
        else:
            print(f"  remove empty dir {d} (after moves)")
    for path in removals:
        print(f"  remove {path}")
        if apply:
            path.unlink()
    if not apply:
        print("(dry run: nothing changed — re-run with --apply)")
    else:
        print("Done. Now run: sudo make deploy-syslog")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--apply", action="store_true",
                        help="perform the migration (default: dry run)")
    parser.add_argument("--log-root", type=Path, default=Path("/var/log"),
                        help="override the log root (for testing)")
    parser.add_argument("--etc-root", type=Path, default=Path("/etc"),
                        help="override the etc root (for testing)")
    args = parser.parse_args(argv)
    migrate(args.log_root, args.etc_root, apply=args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
