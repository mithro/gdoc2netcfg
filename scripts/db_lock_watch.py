#!/usr/bin/env python3
"""Sample /proc/locks for the gdoc2netcfg SQLite DBs and print lock holders.

Usage (as root — /proc/<pid>/cmdline of root daemons needs it):

    sudo .venv/bin/python scripts/db_lock_watch.py [SECONDS] [DB ...]

Defaults: 600 s, .cache/discovery.db and .cache/config.db.  Prints a line
whenever the set of (pid, lock) changes, with how long the previous state
lasted.  SQLite (unix VFS) byte-range locks, relative to 0x40000000:

    PENDING   = byte 0        RESERVED = byte 1       SHARED = bytes 2..511 (READ)
    EXCLUSIVE = bytes 2..511 as WRITE

A SHARED holder that stays for minutes is a long read query; a writer in
PENDING behind it is about to die with "database is locked" after
busy_timeout.  That combination was the 2026-09 outage.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

BASE = 0x40000000


def _lock_name(kind: str, lo: int, hi: int) -> str:
    if (lo, hi) == (0, 0):
        return "PENDING"
    if (lo, hi) == (1, 1):
        return "RESERVED"
    if (lo, hi) == (2, 511):
        return "EXCLUSIVE" if kind == "WRITE" else "SHARED"
    return f"bytes {lo}-{hi} ({kind})"


def _holders(inodes: dict[int, str]) -> set[tuple[str, str, str, str]]:
    out = set()
    for line in Path("/proc/locks").read_text().splitlines():
        f = line.split()
        if len(f) < 8 or f[3] not in ("READ", "WRITE"):
            continue
        inode = int(f[5].rsplit(":", 1)[1])
        if inode not in inodes:
            continue
        pid, kind = f[4], f[3]
        lo, hi = int(f[6]) - BASE, int(f[7]) - BASE
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
            cmd = cmd.decode(errors="replace").strip()[-80:]
        except OSError:
            cmd = "?"
        out.add((inodes[inode], pid, _lock_name(kind, lo, hi), cmd))
    return out


def main(argv: list[str]) -> int:
    seconds = float(argv[1]) if len(argv) > 1 else 600.0
    dbs = argv[2:] or [".cache/discovery.db", ".cache/config.db"]
    inodes = {os.stat(p).st_ino: Path(p).name for p in dbs}
    deadline = time.monotonic() + seconds
    prev: set | None = None
    since = time.monotonic()
    while time.monotonic() < deadline:
        cur = _holders(inodes)
        if cur != prev:
            held = f"{time.monotonic() - since:.0f}s" if prev is not None else "-"
            print(f"{time.strftime('%H:%M:%S')} (previous state held {held})", flush=True)
            for db, pid, name, cmd in sorted(cur):
                print(f"    {db}: pid={pid} {name} :: {cmd}", flush=True)
            if not cur:
                print("    (no locks)", flush=True)
            prev, since = cur, time.monotonic()
        time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
