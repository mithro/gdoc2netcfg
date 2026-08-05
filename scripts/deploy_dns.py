#!/usr/bin/env python3
"""Diff-aware deploy of generated DNS config (dns-redesign layout).

OUT (default ./out) mirrors /etc under out/etc. Deploys, restarting ONLY what
changed:

  dnsmasq leaves   etc/dnsmasq.d/<net>/generated/*.conf  (wipe-and-replace per
                   net: stale generated conf files are removed) -> restart
                   dnsmasq@<net> for changed nets only
  pdns internal    etc/powerdns/bind-internal.conf + zones-internal/*.zone
                   bind conf changed -> systemctl restart pdns@internal
                   only zones changed -> pdns_control bind-reload-now
  pdns external    etc/powerdns/bind-external.conf + zones-external/*.zone
                   bind conf changed -> systemctl restart pdns@external
                   only zones changed -> pdns_control bind-reload-now <zone>
  recursor         etc/powerdns/forward-zones.yml -> restart pdns-recursor

Hand-maintained files are never touched: copies are strictly per-file from
OUT, so `.extra` $INCLUDEs, extra_zones (birds), and hand leaf confs survive.
Zone files that disappear from OUT are left in place (they drop out of the
generated bind conf, which is what matters) and reported.

Ends with a path-scoped etckeeper commit (scripts/etckeeper_commit.py) of the
changed paths only. Run as root (sudo make deploy). --dry-run previews.
"""

import argparse
import subprocess
import sys
from pathlib import Path

ETC = Path("/etc")


def changed(src: Path, dst: Path) -> bool:
    return not dst.exists() or src.read_bytes() != dst.read_bytes()


def run(argv: list[str], dry: bool) -> None:
    print(f"  + {' '.join(argv)}")
    if not dry:
        subprocess.run(argv, check=True)


def copy(src: Path, dst: Path, dry: bool) -> None:
    print(f"  install {dst}")
    if not dry:
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name(dst.name + ".gdoc2netcfg-new")
        tmp.write_bytes(src.read_bytes())
        tmp.chmod(0o644)
        tmp.rename(dst)


def deploy_leaves(out_etc: Path, dry: bool) -> list[Path]:
    touched: list[Path] = []
    leaves_root = out_etc / "dnsmasq.d"
    if not leaves_root.is_dir():
        return touched
    for net_dir in sorted(leaves_root.iterdir()):
        gen = net_dir / "generated"
        if not gen.is_dir():
            continue
        net = net_dir.name
        target = ETC / "dnsmasq.d" / net / "generated"
        if not target.parent.is_dir():
            print(f"  SKIP {net}: no /etc/dnsmasq.d/{net}/ on this host")
            continue
        src_files = {p.name: p for p in sorted(gen.glob("*.conf"))}
        dirty = False
        for name, src in src_files.items():
            if changed(src, target / name):
                copy(src, target / name, dry)
                dirty = True
        for stale in sorted(target.glob("*.conf")):
            if stale.name not in src_files:
                print(f"  remove stale {stale}")
                if not dry:
                    stale.unlink()
                dirty = True
        if dirty:
            run(["systemctl", "restart", f"dnsmasq@{net}"], dry)
            touched.append(target)
    return touched


def deploy_pdns(out_etc: Path, view: str, dry: bool) -> list[Path]:
    """view: 'internal' or 'external'."""
    touched: list[Path] = []
    out_pdns = out_etc / "powerdns"
    bind_conf = out_pdns / f"bind-{view}.conf"
    zones_dir = out_pdns / f"zones-{view}"
    if not zones_dir.is_dir() and not bind_conf.exists():
        return touched

    changed_zones: list[str] = []
    for src in sorted(zones_dir.glob("*.zone")) if zones_dir.is_dir() else []:
        dst = ETC / "powerdns" / f"zones-{view}" / src.name
        if changed(src, dst):
            copy(src, dst, dry)
            touched.append(dst)
            changed_zones.append(src.name.removesuffix(".zone"))
    # Zone files neither generated nor referenced by the (new) bind conf are
    # orphans — hand extra_zones (e.g. birds) ARE referenced, so stay quiet.
    bind_text = bind_conf.read_text() if bind_conf.exists() else ""
    for stale in sorted((ETC / "powerdns" / f"zones-{view}").glob("*.zone")):
        if (zones_dir.is_dir() and not (zones_dir / stale.name).exists()
                and stale.name not in bind_text):
            print(f"  NOTE orphaned zone file left in place: {stale}")

    conf_dst = ETC / "powerdns" / bind_conf.name
    if bind_conf.exists() and changed(bind_conf, conf_dst):
        copy(bind_conf, conf_dst, dry)
        touched.append(conf_dst)
        run(["systemctl", "restart", f"pdns@{view}"], dry)
    elif changed_zones:
        ctl = ["pdns_control", f"--config-name={view}",
               f"--socket-dir=/var/run/pdns-{view}", "bind-reload-now"]
        # internal: reload all; external: per-zone (matches net/CLAUDE.md)
        run(ctl if view == "internal" else ctl + changed_zones, dry)
    return touched


def deploy_recursor(out_etc: Path, dry: bool) -> list[Path]:
    src = out_etc / "powerdns" / "forward-zones.yml"
    dst = ETC / "powerdns" / "forward-zones.yml"
    if not src.exists() or not changed(src, dst):
        return []
    copy(src, dst, dry)
    run(["systemctl", "restart", "pdns-recursor"], dry)
    return [dst]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default="out", help="generator output dir")
    ap.add_argument("--version-label", default="unknown",
                    help="gdoc2netcfg version for the etckeeper message")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    out_etc = Path(args.out) / "etc"
    if not out_etc.is_dir():
        print(f"deploy_dns: {out_etc} missing — run generate first", file=sys.stderr)
        return 2

    touched: list[Path] = []
    print("== dnsmasq leaves ==")
    touched += deploy_leaves(out_etc, args.dry_run)
    print("== pdns internal ==")
    touched += deploy_pdns(out_etc, "internal", args.dry_run)
    print("== pdns external ==")
    touched += deploy_pdns(out_etc, "external", args.dry_run)
    print("== recursor forward-zones ==")
    touched += deploy_recursor(out_etc, args.dry_run)

    if not touched:
        print("Nothing changed — no services restarted.")
        return 0

    if not args.dry_run:
        commit_paths = sorted({str(p) for p in touched})
        r = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "etckeeper_commit.py"),
             "--message",
             f"gdoc2netcfg deploy dns: {args.version_label}", *commit_paths])
        if r.returncode != 0:
            return r.returncode
    print(f"Deployed {len(touched)} changed path(s)."
          " Validate: uv run net/dns-proto/check_walks.py --resolver 10.1.0.1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
