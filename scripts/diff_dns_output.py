"""DNS output diff harness (dns-redesign §7 / plan Task 1.8).

Compares the OLD dnsmasq-generated DNS data against the NEW per-instance
outputs (leaf fragments + pdns zone files) at the resolution level:
every DNS name's effective record sets must survive the redesign except
where an allowlist entry documents the intended difference.

Both sides are parsed into {name: {rrtype: set(values)}}:

- dnsmasq confs (*.conf): host-record=, cname=, ptr-record=, dns-rr=
  (44 → SSHFP, 257 → CAA presence)
- zone files (*.zone): "owner. ttl IN TYPE value" lines, $INCLUDE ignored

CNAME equivalence: a name that is a CNAME on one side and native on the
other counts as EQUAL if the CNAME (chased within its own side's data)
resolves to the same A/AAAA sets — the redesign's projection CNAMEs are
resolution-equivalent to the old site-scoped natives.

Exit status: 0 when every difference matches the allowlist, 1 otherwise.

Usage:
  uv run scripts/diff_dns_output.py \
      --old /etc/dnsmasq.d/internal/generated \
      --new /path/out/dnsmasq-leaf --new /path/out/pdns-internal \
      --allowlist scripts/dns_diff_allowlist.toml
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

ADDRESS_TYPES = ("A", "AAAA")
COMPARE_TYPES = ("A", "AAAA", "PTR", "CNAME", "SSHFP", "CAA")


def _norm(name: str) -> str:
    return name.rstrip(".").lower()


class RecordSet:
    """name → {rrtype: set(values)} with CNAME chasing."""

    def __init__(self) -> None:
        self.records: dict[str, dict[str, set[str]]] = {}

    def add(self, name: str, rrtype: str, value: str) -> None:
        self.records.setdefault(_norm(name), {}).setdefault(
            rrtype, set()
        ).add(value)

    def names(self) -> set[str]:
        return set(self.records)

    def get(self, name: str, rrtype: str) -> set[str]:
        return self.records.get(_norm(name), {}).get(rrtype, set())

    def resolved_addresses(self, name: str, rrtype: str, _depth: int = 0) -> set[str]:
        """The effective addresses of a name, chasing CNAMEs (max 8 hops)."""
        if _depth > 8:
            return set()
        direct = self.get(name, rrtype)
        if direct:
            return direct
        for target in self.get(name, "CNAME"):
            return self.resolved_addresses(target, rrtype, _depth + 1)
        return set()


def parse_dnsmasq_conf(text: str, into: RecordSet) -> None:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("host-record="):
            parts = line[len("host-record="):].split(",")
            name, addrs = parts[0], parts[1:]
            for addr in addrs:
                addr = addr.strip("[]")
                rrtype = "AAAA" if ":" in addr else "A"
                into.add(name, rrtype, addr)
        elif line.startswith("cname="):
            parts = line[len("cname="):].split(",")
            if len(parts) >= 2:
                into.add(parts[0], "CNAME", _norm(parts[-1]))
        elif line.startswith("ptr-record="):
            parts = line[len("ptr-record="):].split(",")
            if len(parts) == 2:
                into.add(parts[0], "PTR", _norm(parts[1]))
        elif line.startswith("dns-rr="):
            parts = line[len("dns-rr="):].split(",")
            if len(parts) >= 3:
                name, rrnum = parts[0], parts[1]
                if rrnum == "44":
                    # normalize alg:fptype:hex → "alg fptype hex"
                    rr = parts[2].replace(":", " ").lower()
                    into.add(name, "SSHFP", rr)
                elif rrnum == "257":
                    into.add(name, "CAA", "letsencrypt")


_ZONE_RE = re.compile(
    r"^(?P<name>\S+)\s+\d+\s+IN\s+(?P<type>[A-Z0-9]+)\s+(?P<value>.+)$"
)


def parse_zone_file(text: str, into: RecordSet) -> None:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith((";", "$")):
            continue
        m = _ZONE_RE.match(line)
        if not m:
            continue
        name, rrtype, value = m.group("name"), m.group("type"), m.group("value")
        if rrtype in ("SOA", "NS"):
            continue  # zone infrastructure, not comparable data
        if rrtype in ("A", "AAAA"):
            into.add(name, rrtype, value.strip())
        elif rrtype in ("CNAME", "PTR"):
            into.add(name, rrtype, _norm(value))
        elif rrtype == "SSHFP":
            into.add(name, "SSHFP", value.strip().lower())
        elif rrtype == "CAA":
            into.add(name, "CAA", "letsencrypt")


def load_dirs(dirs: list[Path]) -> RecordSet:
    rs = RecordSet()
    for d in dirs:
        for path in sorted(d.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix == ".zone":
                parse_zone_file(path.read_text(), rs)
            elif path.suffix == ".conf" and "bind-" not in path.name:
                parse_dnsmasq_conf(path.read_text(), rs)
    return rs


def compare(old: RecordSet, new: RecordSet) -> list[tuple[str, str, str]]:
    """Return differences as (kind, name, detail) tuples.

    kind: 'removed' | 'added' | 'changed'
    """
    diffs: list[tuple[str, str, str]] = []

    for name in sorted(old.names() | new.names()):
        in_old = name in old.records
        in_new = name in new.records

        if in_old and not in_new:
            diffs.append(("removed", name, _summary(old.records[name])))
            continue
        if in_new and not in_old:
            diffs.append(("added", name, _summary(new.records[name])))
            continue

        # Addresses compare CNAME-chased (projection equivalence)
        for rrtype in ADDRESS_TYPES:
            old_addrs = old.resolved_addresses(name, rrtype)
            new_addrs = new.resolved_addresses(name, rrtype)
            if old_addrs != new_addrs:
                diffs.append((
                    "changed",
                    name,
                    f"{rrtype}: {sorted(old_addrs)} -> {sorted(new_addrs)}",
                ))

        # PTR/SSHFP/CAA compare directly
        for rrtype in ("PTR", "SSHFP", "CAA"):
            if old.get(name, rrtype) != new.get(name, rrtype):
                diffs.append((
                    "changed",
                    name,
                    f"{rrtype}: {sorted(old.get(name, rrtype))} -> "
                    f"{sorted(new.get(name, rrtype))}",
                ))

    return diffs


def _summary(rrmap: dict[str, set[str]]) -> str:
    return "; ".join(
        f"{t}={sorted(v)}" for t, v in sorted(rrmap.items())
    )


class Allowlist:
    def __init__(self, entries: list[dict]) -> None:
        self.entries = [
            (
                e["kind"],
                re.compile(e["pattern"]),
                re.compile(e["detail_pattern"]) if e.get("detail_pattern") else None,
                e.get("reason", ""),
            )
            for e in entries
        ]

    @classmethod
    def load(cls, path: Path | None) -> "Allowlist":
        if path is None:
            return cls([])
        data = tomllib.loads(path.read_text())
        return cls(data.get("allow", []))

    def matches(self, kind: str, name: str, detail: str) -> str | None:
        for allow_kind, pattern, detail_pattern, reason in self.entries:
            if allow_kind != kind or not pattern.search(name):
                continue
            if detail_pattern is not None and not detail_pattern.search(detail):
                continue
            return reason or "(allowlisted)"
        return None


def run(
    old_dirs: list[Path],
    new_dirs: list[Path],
    allowlist: Allowlist,
    out=sys.stdout,
) -> int:
    old = load_dirs(old_dirs)
    new = load_dirs(new_dirs)
    diffs = compare(old, new)

    unexpected = 0
    allowed = 0
    for kind, name, detail in diffs:
        reason = allowlist.matches(kind, name, detail)
        if reason is not None:
            allowed += 1
            print(f"ALLOWED {kind.upper()} {name}  [{reason}]", file=out)
        else:
            unexpected += 1
            print(f"{kind.upper()} {name}  {detail}", file=out)

    print(
        f"\n{len(old.names())} old names, {len(new.names())} new names, "
        f"{len(diffs)} differences ({allowed} allowlisted, "
        f"{unexpected} unexpected)",
        file=out,
    )
    return 0 if unexpected == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", action="append", required=True, type=Path)
    parser.add_argument("--new", action="append", required=True, type=Path)
    parser.add_argument("--allowlist", type=Path)
    args = parser.parse_args(argv)
    return run(args.old, args.new, Allowlist.load(args.allowlist))


if __name__ == "__main__":
    sys.exit(main())
