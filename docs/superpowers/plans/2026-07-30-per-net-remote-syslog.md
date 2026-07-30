# Per-Net Remote Syslog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Per-net remote syslog capture on the site routers — one rsyslog input per VLAN leg on UDP 514 writing `/var/log/<netname>/<hostname>.log` — generated from inventory, plus a one-off migration of the old tasmota/network directories and a wisp-pushed re-target of the wifi fleet's `logd`.

**Architecture:** A new `rsyslog` generator in gdoc2netcfg derives the served legs from the router's inventory interfaces (the same rule as the DNS leaf gateways), emitting one rsyslog drop-in + one logrotate file (deploy-relative under `etc/`, like the DNS stack). A migration script moves the legacy `/var/log/tasmota` + `/var/log/network` contents into `/var/log/iot` + `/var/log/net` and removes the superseded hand-written configs. In gwifi-openwrt, the `ansells-aps-base` post-reload-hook stops hardcoding wisp:6666 and targets `{{ syslog_ip }}`:514 (template `default_values`).

**Tech Stack:** Python 3.12 (`uv run`), pytest, rsyslog `imudp`/dynafile, logrotate, OpenWISP templates (netjsonconfig var substitution).

**Spec:** `docs/superpowers/specs/2026-07-30-per-net-remote-syslog-design.md` (read it first; it is the contract).

**Worktrees:** Tasks 1–7 run in gdoc2netcfg worktree `.worktrees/wifi-syslog` (branch `wifi-syslog`, already created). Task 8 runs in gwifi-openwrt — create worktree first: `cd /home/tim/local/gwifi/gwifi-openwrt && git worktree add .worktrees/wifi-syslog -b wifi-syslog origin/main`.

**Phase 2 (rollout/deployment) is controller-run, NOT part of subagent execution** — listed at the end for completeness.

**File structure (Phase 1):**

| File | Responsibility |
|---|---|
| `src/gdoc2netcfg/generators/rsyslog.py` (create) | Served-leg derivation + rsyslog drop-in + logrotate emission |
| `tests/test_generators/test_rsyslog.py` (create) | Generator unit tests |
| `scripts/migrate-remote-syslog.py` (create) | One-off per-site dir/config migration (importable, dry-run default) |
| `tests/test_scripts/test_migrate_remote_syslog.py` (create) | Migration tests on tmp_path trees |
| `src/gdoc2netcfg/cli/main.py` (modify) | Generator registry entry |
| `gdoc2netcfg.toml.example` (modify) | `[generators.rsyslog]` + enabled-list mention |
| `Makefile` (modify) | `deploy-syslog` rewrite |
| `etc/rsyslog-tasmota.conf`, `etc/logrotate-tasmota` (delete) | Superseded by generator |
| `CLAUDE.md` (modify) | Syslog section rewrite |
| gwifi-openwrt `openwisp/build-templates.py` (modify) | Hook re-target + `syslog_ip` default |

---

### Task 1: `rsyslog` generator — served legs + rsyslog drop-in

**Files:**
- Create: `src/gdoc2netcfg/generators/rsyslog.py`
- Create: `tests/test_generators/test_rsyslog.py`

Context for the implementer: `recursor_forward._leaf_gateways(inventory)` returns `dict[net, [v4, v6...]]` from the ROUTER_HOSTNAME (`ten64`) host's interfaces, already excluding non-leaf nets (wg/transit/delegated). Look at `tests/test_generators/test_dnsmasq_leaf.py` for the SITE-fixture idiom (`Site`, `VLAN`, `NetworkInterface`, `derive_all_dns_names`); the router host must be *named* `ten64` (that is `pdns_zones.ROUTER_HOSTNAME`).

- [ ] **Step 1: Write the failing tests**

```python
"""Tests for the rsyslog remote-capture generator."""

from gdoc2netcfg.derivations.dns_names import derive_all_dns_names
from gdoc2netcfg.generators.rsyslog import generate_rsyslog
from gdoc2netcfg.models.addressing import IPv4Address, IPv6Address, MACAddress
from gdoc2netcfg.models.host import Host, NetworkInterface, NetworkInventory
from gdoc2netcfg.models.network import VLAN, IPv6Prefix, Site

SITE = Site(
    name="welland",
    domain="welland.mithis.com",
    site_octet=1,
    vlans={
        1: VLAN(id=1, name="tmp", subdomain="tmp", third_octets=(1,)),
        4: VLAN(id=4, name="wifi", subdomain="wifi", third_octets=(4,)),
        5: VLAN(id=5, name="net", subdomain="net", third_octets=(5,)),
        90: VLAN(id=90, name="iot", subdomain="iot", third_octets=(90, 91)),
        99: VLAN(id=99, name="guest", subdomain="guest", third_octets=(99,)),
    },
    ipv6_prefixes=[IPv6Prefix(prefix="2404:e80:a137:", name="Launtel")],
    # LOAD-BEARING: ip_to_net() classifies site-octet addresses via
    # network_subdomains (NOT vlans) — without this map _leaf_gateways
    # returns {} and every test fails pointing at the wrong place.
    network_subdomains={1: "tmp", 4: "wifi", 5: "net",
                        90: "iot", 91: "iot", 99: "guest"},
)


def _leg(name, suffix, v4, v6=None):
    ips = [IPv4Address(v4)]
    if v6:
        ips.append(IPv6Address(v6, "2404:e80:a137:"))
    return NetworkInterface(
        name=name,
        mac=MACAddress.parse(f"02:00:0a:01:00:{suffix}"),
        ip_addresses=tuple(ips),
        dhcp_name=f"{name}-ten64",
    )


def _inventory(interfaces):
    router = Host(machine_name="ten64", hostname="ten64", interfaces=interfaces)
    derive_all_dns_names(router, SITE)
    return NetworkInventory(site=SITE, hosts=[router])


def _default_inventory():
    return _inventory([
        _leg("br-wifi", "01", "10.1.4.1", "2404:e80:a137:104::1"),
        _leg("br-net", "02", "10.1.5.1"),
        _leg("br-iot", "03", "10.1.90.1"),
        _leg("br-tmp", "04", "10.1.1.1"),
        _leg("br-guest", "05", "10.1.99.1"),
    ])


class TestRsyslogConf:
    def test_one_input_per_served_leg_on_514(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert ('input(type="imudp" port="514" address="10.1.4.1" '
                'ruleset="remote-wifi")') in conf
        assert ('input(type="imudp" port="514" address="10.1.5.1" '
                'ruleset="remote-net")') in conf
        assert ('input(type="imudp" port="514" address="10.1.90.1" '
                'ruleset="remote-iot")') in conf

    def test_tmp_and_guest_excluded(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert "10.1.1.1" not in conf
        assert "10.1.99.1" not in conf
        assert "remote-tmp" not in conf
        assert "remote-guest" not in conf

    def test_v4_only_inputs(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert "2404:e80:a137:104::1" not in conf

    def test_single_imudp_module_load(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('module(load="imudp")') == 1

    def test_ruleset_writes_secpath_dynafile_and_stops(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert ('string="/var/log/wifi/%hostname:::secpath-replace%.log"') in conf
        assert 'fileOwner="root" fileGroup="adm"' in conf
        assert 'fileCreateMode="0640" dirCreateMode="0755"' in conf
        assert "stop" in conf

    def test_transition_input_10514_targets_remote_net(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert 'input(type="imudp" port="10514" ruleset="remote-net")' in conf

    def test_no_leg_no_input(self):
        inv = _inventory([
            _leg("br-net", "02", "10.1.5.1"),
            _leg("br-iot", "03", "10.1.90.1"),
        ])
        conf = generate_rsyslog(inv)["rsyslog.d/remote-logs.conf"]
        assert "remote-wifi" not in conf

    def test_no_net_leg_fails_loud(self):
        import pytest
        inv = _inventory([_leg("br-iot", "03", "10.1.90.1")])
        with pytest.raises(ValueError, match="net"):
            generate_rsyslog(inv)

    def test_no_served_legs_fails_loud(self):
        import pytest
        inv = _inventory([_leg("br-tmp", "04", "10.1.1.1")])
        with pytest.raises(ValueError):
            generate_rsyslog(inv)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_generators/test_rsyslog.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'gdoc2netcfg.generators.rsyslog'`

- [ ] **Step 3: Write the generator (rsyslog drop-in half)**

```python
"""rsyslog remote-capture generator (per-net remote syslog design).

One imudp input per served router leg, all on UDP 514 — the log class is
the net the message arrives on. Messages are written to
/var/log/<netname>/<hostname>.log via a per-net dynafile ruleset.

Served nets = the router's leaf-net legs (recursor_forward._leaf_gateways,
i.e. the same derivation as the DNS leaf gateways) minus the untrusted
tmp/guest nets. v4 only — every current sender targets v4.

Safety properties (carried over from the hand-written files this
replaces): remote messages only reach the per-device files (ruleset
isolation + stop), never /var/log/syslog; local messages never reach the
remote dirs; secpath-replace prevents hostile hostnames escaping the
directory; dynafile dirs are auto-created (0755, files root:adm 0640).

A transition input on 10514 feeds remote-net so existing switch/wisp
senders keep logging until they are re-pointed at <net-leg>:514
(dropping it is a documented follow-up, spec §out-of-scope).
"""

from __future__ import annotations

from gdoc2netcfg.generators.recursor_forward import _leaf_gateways
from gdoc2netcfg.models.host import NetworkInventory

# Untrusted nets never get a syslog input.
EXCLUDED_NETS = frozenset({"tmp", "guest"})

_HEADER = """\
# Generated by gdoc2netcfg (rsyslog) — do not edit.
# Per-net remote syslog capture: one imudp input per router leg, all on
# UDP 514; the class is the net the message arrives on. Replaces the
# hand-written tasmota.conf + z-network-switches.conf (this file now
# performs the single allowed imudp module load).
module(load="imudp")
"""

_TRANSITION = """\
# Transition input: switches + wisp still send to :10514 — keep feeding
# them into /var/log/net/ until they are re-pointed at the net leg :514.
input(type="imudp" port="10514" ruleset="remote-net")
"""


def _served_legs(inventory: NetworkInventory) -> dict[str, str]:
    """net -> the router's v4 leg address, tmp/guest excluded."""
    legs: dict[str, str] = {}
    for net, forwarders in _leaf_gateways(inventory).items():
        if net in EXCLUDED_NETS:
            continue
        v4 = [a for a in forwarders if ":" not in a]
        if v4:
            legs[net] = v4[0]
    return legs


def _net_block(net: str, addr: str) -> str:
    return f"""\
template(name="RemoteLog-{net}" type="string"
         string="/var/log/{net}/%hostname:::secpath-replace%.log")
ruleset(name="remote-{net}") {{
    action(type="omfile" dynaFile="RemoteLog-{net}"
           fileOwner="root" fileGroup="adm"
           fileCreateMode="0640" dirCreateMode="0755")
    stop
}}
input(type="imudp" port="514" address="{addr}" ruleset="remote-{net}")
"""


def generate_rsyslog(inventory: NetworkInventory) -> dict[str, str]:
    """Generate the rsyslog drop-in + logrotate file.

    Returns deploy-relative paths under etc/ ([generators.rsyslog]
    output_dir = "etc"): rsyslog.d/remote-logs.conf and
    logrotate.d/remote-logs.
    """
    legs = _served_legs(inventory)
    if not legs:
        raise ValueError(
            "rsyslog generator: router has no served legs — check the "
            "inventory has a 'ten64' host with leaf-net interfaces"
        )
    if "net" not in legs:
        raise ValueError(
            "rsyslog generator: router has no 'net' leg — the 10514 "
            "transition input needs the remote-net ruleset"
        )

    parts = [_HEADER]
    parts.extend(_net_block(net, legs[net]) for net in sorted(legs))
    parts.append(_TRANSITION)
    return {
        "rsyslog.d/remote-logs.conf": "\n".join(parts),
        "logrotate.d/remote-logs": _logrotate(sorted(legs)),
    }
```

(`_logrotate` comes in Task 2 — for this step stub it as
`def _logrotate(nets): return ""` so the conf tests can go green first.)

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_generators/test_rsyslog.py -q`
Expected: PASS (all TestRsyslogConf tests)

- [ ] **Step 5: Commit**

```bash
git add src/gdoc2netcfg/generators/rsyslog.py tests/test_generators/test_rsyslog.py
git commit -m "feat(generators): rsyslog per-net remote-capture drop-in"
```

---

### Task 2: logrotate emission

**Files:**
- Modify: `src/gdoc2netcfg/generators/rsyslog.py` (replace the `_logrotate` stub)
- Test: `tests/test_generators/test_rsyslog.py`

- [ ] **Step 1: Write the failing tests** (append to the test file)

```python
class TestLogrotate:
    def test_stanza_per_served_net_with_year_floor_policy(self):
        rot = generate_rsyslog(_default_inventory())["logrotate.d/remote-logs"]
        for net in ("wifi", "net", "iot"):
            assert f"/var/log/{net}/*.log {{" in rot
        # the 1-year-floor policy, verbatim from the retired etc/logrotate-tasmota
        assert rot.count("rotate 400") == 3
        for directive in ("daily", "compress", "delaycompress",
                          "missingok", "notifempty",
                          "/usr/lib/rsyslog/rsyslog-rotate"):
            assert directive in rot

    def test_no_stanza_for_excluded_or_legless_nets(self):
        rot = generate_rsyslog(_default_inventory())["logrotate.d/remote-logs"]
        assert "/var/log/tmp/" not in rot
        assert "/var/log/guest/" not in rot
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_generators/test_rsyslog.py::TestLogrotate -q`
Expected: FAIL (empty logrotate output)

- [ ] **Step 3: Implement `_logrotate`**

```python
_LOGROTATE_HEADER = """\
# Generated by gdoc2netcfg (rsyslog) — do not edit.
# Retention: keep at least one year of daily logs. `notifempty` skips days
# a device sent nothing, so 400 daily archives span >=400 days for a
# chatty device and longer for an intermittent one, comfortably clearing
# the 1-year floor. No maxage: nothing is removed by age, only once the
# count is exceeded.
"""


def _logrotate(nets: list[str]) -> str:
    stanzas = [_LOGROTATE_HEADER]
    for net in nets:
        stanzas.append(f"""\
/var/log/{net}/*.log {{
    daily
    rotate 400
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}}
""")
    return "\n".join(stanzas)
```

- [ ] **Step 4: Run the whole test file** — `uv run pytest tests/test_generators/test_rsyslog.py -q` — PASS

- [ ] **Step 5: Commit** — `git commit -am "feat(generators): rsyslog logrotate emission (1-year-floor policy)"`

---

### Task 3: registry + example-toml wiring

**Files:**
- Modify: `src/gdoc2netcfg/cli/main.py` (the generator registry dict, ~line 714 — add after `"wifi"`)
- Modify: `gdoc2netcfg.toml.example` (after `[generators.pdns_external]`-area sections)
- Test: `tests/test_generators/test_rsyslog.py`

- [ ] **Step 1: Failing test** (append)

```python
class TestRegistry:
    def test_rsyslog_resolves_in_cli_registry(self):
        from gdoc2netcfg.cli import main as cli_main
        func = cli_main._get_generator("rsyslog")
        assert func is generate_rsyslog
```

(If the registry helper's real name differs from `_get_generator`, use the
actual function that contains the dict at cli/main.py:714 — follow how the
`"wifi"` entry was added.)

- [ ] **Step 2: Run — FAIL** (returns None / KeyError)

- [ ] **Step 3: Add the registry line**

```python
        "rsyslog": ("gdoc2netcfg.generators.rsyslog", "generate_rsyslog"),
```

And in `gdoc2netcfg.toml.example` add (mirroring the dnsmasq_leaf comment style):

```toml
# Per-net remote syslog capture (rsyslog drop-in + logrotate; out/etc
# mirrors /etc — deployed by `sudo make deploy-syslog`).
[generators.rsyslog]
output_dir = "etc"
```

and mention `"rsyslog"` in the comment near the example `enabled = [...]`
list as a both-sites generator (do NOT change the literal example list if
the surrounding comment says sites edit it — match local style).

- [ ] **Step 4: Run full test file + lint** — `uv run pytest tests/test_generators/test_rsyslog.py -q && uv run ruff check src/ tests/` — PASS

- [ ] **Step 5: Commit** — `git commit -am "feat(cli): register rsyslog generator + example config"`

---

### Task 4: migration script

**Files:**
- Create: `scripts/migrate-remote-syslog.py`
- Create: `tests/test_scripts/test_migrate_remote_syslog.py`

The script is importable (module-level functions, no work at import).
Import it the way `tests/test_scripts/test_wifi_sheet_migrate.py` does —
`importlib.util.spec_from_file_location` with a `__file__`-relative path
(robust regardless of pytest's cwd):

- [ ] **Step 1: Failing tests**

```python
"""Tests for scripts/migrate-remote-syslog.py on tmp_path trees."""

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/migrate-remote-syslog.py"
_spec = importlib.util.spec_from_file_location("migrate_remote_syslog", _SCRIPT)
mrs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mrs)


def _make_tree(tmp_path):
    log = tmp_path / "var/log"
    etc = tmp_path / "etc"
    (log / "tasmota").mkdir(parents=True)
    (log / "network").mkdir(parents=True)
    (log / "tasmota/au-plug-1.log").write_text("t\n")
    (log / "tasmota/au-plug-1.log.1.gz").write_text("z\n")
    (log / "network/wisp.log").write_text("n\n")
    (etc / "rsyslog.d").mkdir(parents=True)
    (etc / "logrotate.d").mkdir(parents=True)
    (etc / "rsyslog.d/tasmota.conf").write_text("old\n")
    (etc / "rsyslog.d/z-network-switches.conf").write_text("old\n")
    (etc / "logrotate.d/tasmota").write_text("old\n")
    # a hand-deployed network-class logrotate file (spec: detect + remove)
    (etc / "logrotate.d/network-devices").write_text("/var/log/network/*.log {}\n")
    return log, etc


def test_dry_run_reports_and_touches_nothing(tmp_path, capsys):
    log, etc = _make_tree(tmp_path)
    mrs.migrate(log, etc, apply=False)
    out = capsys.readouterr().out
    assert "au-plug-1.log" in out and "wisp.log" in out
    assert (log / "tasmota/au-plug-1.log").exists()
    assert (etc / "rsyslog.d/tasmota.conf").exists()


def test_apply_moves_files_and_removes_configs(tmp_path):
    log, etc = _make_tree(tmp_path)
    mrs.migrate(log, etc, apply=True)
    assert (log / "iot/au-plug-1.log").read_text() == "t\n"
    assert (log / "iot/au-plug-1.log.1.gz").exists()
    assert (log / "net/wisp.log").read_text() == "n\n"
    assert not (log / "tasmota").exists()
    assert not (log / "network").exists()
    assert not (etc / "rsyslog.d/tasmota.conf").exists()
    assert not (etc / "rsyslog.d/z-network-switches.conf").exists()
    assert not (etc / "logrotate.d/tasmota").exists()
    assert not (etc / "logrotate.d/network-devices").exists()


def test_apply_is_idempotent(tmp_path):
    log, etc = _make_tree(tmp_path)
    mrs.migrate(log, etc, apply=True)
    mrs.migrate(log, etc, apply=True)  # second run: everything absent, no error
    assert (log / "iot/au-plug-1.log").exists()


def test_refuses_on_would_overwrite_conflict(tmp_path):
    log, etc = _make_tree(tmp_path)
    (log / "iot").mkdir()
    (log / "iot/au-plug-1.log").write_text("existing\n")
    with pytest.raises(SystemExit):
        mrs.migrate(log, etc, apply=True)
    # nothing was moved on refusal
    assert (log / "tasmota/au-plug-1.log").read_text() == "t\n"
```

- [ ] **Step 2: Run — FAIL** (`ModuleNotFoundError`)

- [ ] **Step 3: Implement**

```python
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
file already exists. Does NOT touch rsyslog or install new configs — run
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
        if apply and d.is_dir():
            d.rmdir()  # fails loud if anything unexpected remains
            print(f"  removed empty {d}")
    for path in removals:
        print(f"  remove {path}")
        if apply:
            path.unlink()
    if not apply:
        print("(dry run: nothing changed — re-run with --apply)")
    else:
        print("Done. Now run: sudo make deploy-syslog")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="perform the migration (default: dry run)")
    parser.add_argument("--log-root", type=Path, default=Path("/var/log"))
    parser.add_argument("--etc-root", type=Path, default=Path("/etc"))
    args = parser.parse_args(argv)
    migrate(args.log_root, args.etc_root, apply=args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests** — `uv run pytest tests/test_scripts/test_migrate_remote_syslog.py -q` — PASS

- [ ] **Step 5: Commit** — `git add scripts/migrate-remote-syslog.py tests/test_scripts/test_migrate_remote_syslog.py && git commit -m "feat(scripts): one-off migration to per-net remote syslog layout"`

---

### Task 5: Makefile rewrite + retire hand-written files

**Files:**
- Modify: `Makefile` (lines ~117–127: the syslog vars + `deploy-syslog` target)
- Delete: `etc/rsyslog-tasmota.conf`, `etc/logrotate-tasmota`

- [ ] **Step 1: Rewrite the target**

Replace the three variables and the target with:

```make
RSYSLOG_REMOTE_CONF := /etc/rsyslog.d/remote-logs.conf
LOGROTATE_REMOTE_CONF := /etc/logrotate.d/remote-logs

.PHONY: deploy-syslog
deploy-syslog: $(VENV)/.stamp ## Deploy generated per-net remote syslog + logrotate config (run with sudo)
	$(VENV_BIN)/gdoc2netcfg generate rsyslog --output-dir out
	cp out/etc/rsyslog.d/remote-logs.conf $(RSYSLOG_REMOTE_CONF)
	cp out/etc/logrotate.d/remote-logs $(LOGROTATE_REMOTE_CONF)
	systemctl restart rsyslog
	$(ETCKEEPER_COMMIT) "gdoc2netcfg deploy syslog: $(GDOC2NETCFG_VERSION)" /etc/rsyslog.d /etc/logrotate.d
```

Notes: no `install -d` — dynafile dirs auto-create. The etckeeper paths
are the whole `.d` dirs so the commit captures the migration's removals
too. Match the existing target's prerequisite/variable idioms exactly —
neighbouring deploy targets use `$(VENV_BIN)/gdoc2netcfg` (NOT `uv run`,
which under sudo on prod would re-sync the root-owned venv; see
CLAUDE.md's SQLite-ownership note). Verify against the neighbours before
committing.

- [ ] **Step 2: Delete the retired files**

```bash
git rm etc/rsyslog-tasmota.conf etc/logrotate-tasmota
```

- [ ] **Step 3: Verify** — `make -n deploy-syslog` prints the new recipe; `uv run pytest -q` still green (nothing imports the deleted files).

- [ ] **Step 4: Commit** — `git commit -am "feat(make): deploy-syslog deploys the generated per-net files"`

---

### Task 6: CLAUDE.md rewrite

**Files:**
- Modify: `CLAUDE.md` — the "Tasmota remote syslog" section (~line 513) and the build-commands list (add `uv run gdoc2netcfg generate rsyslog`).

- [ ] **Step 1: Rewrite the section** as "Per-net remote syslog" describing: the classification rule (one input per served leg on 514, class = arrival net, tmp/guest excluded), `/var/log/<net>/<hostname>.log`, the generator + `make deploy-syslog`, the 10514 transition input for switches/wisp, the migration script (one-off, already run once both sites — write it as current-state after rollout), the actual retention policy (rotate 400, 1-year floor — fixing the stale "14 kept" claim), and where each sender class lands (tasmota→iot, switches/wisp→net, pucks/tenwrt→wifi). Keep the `tasmota configure` device-side paragraph (syslog_host resolution) — it still applies, unchanged.

- [ ] **Step 2: Commit** — `git commit -am "docs: per-net remote syslog section (replaces tasmota-only syslog docs)"`

---

### Task 7: acceptance sweep + push + PR (gdoc2netcfg)

- [ ] **Step 1:** `uv run pytest -q` (gate: 0 failures) and `uv run ruff check src/ tests/` (gate: clean)
- [ ] **Step 2:** Also fix the spec's Problem-section wording while here: the wisp:6666 stanza lives in the *ansells-aps-base post-reload-hook* (OpenWISP-delivered), not the image bootstrap; the image sets nothing (verified by grep across `*-image/`). One-paragraph correction in the spec, committed as `docs: spec correction — syslog stanza lives in the base-template hook, not the image`.
- [ ] **Step 3:** `git push -u origin wifi-syslog` and open a PR titled "generators: per-net remote syslog capture + one-off migration" with a summary referencing the spec; CI must be green.

---

### Task 8: gwifi-openwrt — base-template hook re-target

**Worktree:** `cd /home/tim/local/gwifi/gwifi-openwrt && git worktree add .worktrees/wifi-syslog -b wifi-syslog origin/main && cd .worktrees/wifi-syslog`

**Files:**
- Modify: `openwisp/build-templates.py` — the POST_RELOAD_HOOK string (~line 247) and the template `default_values` construction (find where the DEFAULTS dict is built from `read_passphrases()`).

- [ ] **Step 1: Re-target the hook stanza**

Replace:

```sh
# Remote syslog to wisp.
uci set system.@system[0].log_ip='10.1.4.2'
uci set system.@system[0].log_port='6666'
uci set system.@system[0].log_proto='udp'
```

with:

```sh
# Remote syslog to the site router's wifi leg (per-net remote syslog
# design, gdoc2netcfg 2026-07-30): /var/log/wifi/<hostname>.log on ten64.
# {{ syslog_ip }} comes from the template default_values (site default
# 10.1.4.1; override per device/group for other sites). Kernel netconsole
# to wisp:6666 is separate and unchanged.
uci set system.@system[0].log_ip='{{ syslog_ip }}'
uci set system.@system[0].log_port='514'
uci set system.@system[0].log_proto='udp'
```

- [ ] **Step 2: Add the context default**

Add `"syslog_ip": "10.1.4.1"` to the DEFAULTS/default_values dict (same
dict that carries the passphrases — find its construction site; it is
passed as `default_values=DEFAULTS` in the Django upsert block). CRITICAL
known gotcha: netjsonconfig renders the literal `{{ syslog_ip }}` string
onto devices if the context key is missing — the default MUST land in the
same `default_values` the base template already uses.

- [ ] **Step 3: Add the template-builder test (spec Testing requirement)**

gwifi-openwrt has no repo-root pytest harness (only
`tools/gwifi-netboot` has its own), so create
`tests/openwisp/test_build_templates.py` as a standalone pytest file
doing **text-level** assertions on the script source (build-templates.py
executes work at import time — never import it in tests):

```python
"""Text-level checks on openwisp/build-templates.py (it runs at import,
so tests assert on the source, not the module)."""

from pathlib import Path

SRC = (Path(__file__).resolve().parents[2]
       / "openwisp/build-templates.py").read_text()


def test_hook_targets_syslog_ip_variable_on_514():
    assert "uci set system.@system[0].log_ip='{{ syslog_ip }}'" in SRC
    assert "uci set system.@system[0].log_port='514'" in SRC


def test_hook_no_longer_hardcodes_wisp_syslog_target():
    assert "log_ip='10.1.4.2'" not in SRC
    assert "log_port='6666'" not in SRC


def test_defaults_carry_the_syslog_ip_context():
    # the default MUST live in the same default_values the base template
    # uses, or devices render the literal {{ syslog_ip }} string
    assert '"syslog_ip": "10.1.4.1"' in SRC
```

Run: `uv run --with pytest pytest tests/openwisp/ -q` — expected PASS
(write the test AFTER steps 1–2; then also re-run it with the edits
reverted via `git stash` to confirm it fails, `git stash pop` after).

- [ ] **Step 4: Verify by grep**

```bash
grep -n "6666" openwisp/build-templates.py   # only netconsole comments, no uci log_ip line
grep -n "syslog_ip" openwisp/build-templates.py  # hook stanza + DEFAULTS entry
```

- [ ] **Step 5: Commit + push + PR**

```bash
git add openwisp/build-templates.py tests/openwisp/test_build_templates.py
git commit -m "openwisp: base template points logd at the site router's wifi leg (:514)"
git push -u origin wifi-syslog
```

Open a PR against gwifi-openwrt main referencing the gdoc2netcfg spec.

---

## Phase 2 — rollout (controller-run, NOT for subagents)

Recorded for completeness; requires prod access and user-visible windows.

1. Merge both PRs; pull `/opt/gdoc2netcfg` on both ten64s.
2. Per site: add `"rsyslog"` to `[generators] enabled` + `[generators.rsyslog] output_dir = "etc"` in the prod toml; `sudo uv run scripts/migrate-remote-syslog.py` (review dry-run) then `--apply`; `sudo make deploy-syslog`; check `ss -ulpn | grep 514` shows one socket per served leg + 10514.
3. wisp: edit `/etc/rsyslog.d/90-forward-ten64.conf` target to `10.1.4.1:514`; restart rsyslog; confirm `/var/log/wifi/wisp.log` grows on ten64.
4. gwifi-openwrt: check the standing MT7915 single-phy caveat before re-running `build-templates.py`; re-run it; push config to the 12 pucks + tenwrt.
5. Live verification (spec list): `logger` from a puck → `/var/log/wifi/<puck>.log`; tasmota lands in `/var/log/iot/`; switches still land via 10514 → `/var/log/net/`; `/var/log/syslog` clean; `logd` lines stop arriving at `/var/log/gale-netconsole/` while kernel netconsole lines continue.
6. Follow-ups (out of scope, note in memory): re-point switches to `10.X.5.1:514`, then drop the 10514 transition input from the generator.
