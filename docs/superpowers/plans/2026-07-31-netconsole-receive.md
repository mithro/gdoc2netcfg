# Netconsole Receive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the `rsyslog` generator so every served router leg also receives kernel netconsole datagrams (UDP 6666) into `/var/log/<net>/<sender>.kernel.log`, separate from the syslog streams.

**Architecture:** Pure receive-side extension of the existing per-net remote syslog design (spec: `docs/superpowers/specs/2026-07-31-netconsole-receive-design.md`; parent: `2026-07-30-per-net-remote-syslog-design.md`). Each served net's block in `remote-logs.conf` gains a second ruleset + a leg-bound port-6666 `imudp` input. Netconsole payloads are raw printk (no syslog header, no hostname), so the dynafile keys on `%fromhost%` (sender reverse-DNS) and a shared `KernelLine` template stamps wall-clock arrival + `%rawmsg%`. No sender-side change ships — pucks keep streaming to wisp:6666 until a documented follow-up re-points them. Logrotate is untouched: the existing `/var/log/<net>/*.log` globs already match `*.kernel.log` (a pin test enforces this).

**Tech Stack:** Python 3.11+ (`uv run`), pytest, rsyslog RainerScript (imudp/omfile/dynafile).

**Working directory:** `/home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog` (branch `wifi-syslog`, PR #24 — this work extends that PR; do NOT create a new branch).

**Conventions:** All Python via `uv run`. Never redirect stderr to `/dev/null`. Commits end with:

```
Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BSHiudkQxHncLaoZeKPMDt
```

---

## File structure

- Modify: `src/gdoc2netcfg/generators/rsyslog.py` — module docstring paragraph, `_HEADER` gains the shared `KernelLine` template, new `_kernel_block()`, `generate_rsyslog()` interleaves kernel blocks.
- Modify: `tests/test_generators/test_rsyslog.py` — new `TestNetconsole` class, one updated count in `TestRsyslogConf`, one new pin test in `TestLogrotate`.
- Modify: `CLAUDE.md` — one paragraph in the "Per-net remote syslog" section.

No other files change. `logrotate.d/remote-logs` emission, the CLI registry, the Makefile, and the migration script are all untouched.

---

### Task 1: Kernel netconsole blocks in the generator (TDD)

**Files:**
- Modify: `src/gdoc2netcfg/generators/rsyslog.py`
- Test: `tests/test_generators/test_rsyslog.py`

- [ ] **Step 1: Write the failing tests**

Append this class to `tests/test_generators/test_rsyslog.py` (after `TestRsyslogConf`, before `TestLogrotate`). The existing fixtures (`SITE`, `_leg`, `_inventory`, `_default_inventory`) are reused as-is — served nets in the default inventory are `iot`, `net`, `wifi` (tmp/guest excluded), legs 10.1.90.1 / 10.1.5.1 / 10.1.4.1.

```python
class TestNetconsole:
    def test_kernel_input_per_served_leg_on_6666(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert ('input(type="imudp" port="6666" address="10.1.4.1" '
                'ruleset="remote-wifi-kernel")') in conf
        assert ('input(type="imudp" port="6666" address="10.1.5.1" '
                'ruleset="remote-net-kernel")') in conf
        assert ('input(type="imudp" port="6666" address="10.1.90.1" '
                'ruleset="remote-iot-kernel")') in conf
        assert conf.count('port="6666"') == 3

    def test_kernel_dynafile_keys_on_fromhost_with_kernel_suffix(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        # sender reverse-DNS, NOT %hostname% — netconsole payloads carry none
        assert ('string="/var/log/wifi/%fromhost:::secpath-replace%'
                '.kernel.log"') in conf
        assert conf.count("%fromhost:::secpath-replace%.kernel.log") == 3

    def test_kernel_line_template_defined_once_stamps_arrival_and_rawmsg(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('template(name="KernelLine"') == 1
        assert "%timegenerated:::date-rfc3339%" in conf
        # literal backslash-n in the emitted config (rsyslog escape, not Python's)
        assert r"%rawmsg:::drop-last-lf%\n" in conf

    def test_kernel_actions_use_kernel_line_template(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('template="KernelLine"') == 3

    def test_kernel_rulesets_isolated_and_tmp_guest_excluded(self):
        conf = generate_rsyslog(_default_inventory())["rsyslog.d/remote-logs.conf"]
        assert conf.count('-kernel") {') == 3
        assert "remote-tmp-kernel" not in conf
        assert "remote-guest-kernel" not in conf
```

Then update ONE existing assertion — `TestRsyslogConf.test_ruleset_writes_secpath_dynafile_and_stops` currently ends with:

```python
        assert conf.count("    stop") == 3
```

Change it to (3 syslog rulesets + 3 kernel rulesets, each `stop`-isolated):

```python
        assert conf.count("    stop") == 6
```

- [ ] **Step 2: Run the tests to verify they fail (and only the expected ones)**

Run: `cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog && uv run pytest tests/test_generators/test_rsyslog.py -v`

Expected: the 5 `TestNetconsole` tests FAIL (assertions on missing config text) and `test_ruleset_writes_secpath_dynafile_and_stops` FAILS (count is 3, expects 6). All other tests still PASS. If anything else fails, stop and investigate.

- [ ] **Step 3: Implement**

In `src/gdoc2netcfg/generators/rsyslog.py`:

**(a)** Append to the module docstring (after the transition-input paragraph):

```
Kernel netconsole capture rides the same file: one leg-bound imudp input
per served net on UDP 6666 (the fleet's netconsole port), ruleset
remote-<net>-kernel, files /var/log/<net>/<sender>.kernel.log. Netconsole
payloads are raw printk — no syslog header, no hostname — so filenames
key on the sender's reverse-DNS name (fromhost; PTR coverage comes from
the DNS stack, unresolvable senders degrade to their bare IP) and the
shared KernelLine template stamps wall-clock arrival next to the raw
payload (whose level,seq,monotonic-ts prefix survives for gap
detection). Receive-only for now: the pucks still stream to wisp:6666;
re-pointing them (and retiring wisp's receiver) is a documented
follow-up, like the 10514 transition input.
```

**(b)** Extend `_HEADER` (the `KernelLine` template is shared by every kernel action, so it is defined once here — note the `\\n`: the emitted config must contain a literal `\n` rsyslog escape):

```python
_HEADER = """\
# Generated by gdoc2netcfg (rsyslog) — do not edit.
# Per-net remote syslog capture: one imudp input per router leg, all on
# UDP 514; the class is the net the message arrives on. Replaces the
# hand-written tasmota.conf + z-network-switches.conf (this file now
# performs the single allowed imudp module load).
module(load="imudp")

# Kernel netconsole capture: raw printk datagrams (no syslog header, no
# hostname) arrive on UDP 6666, one leg-bound input per served net.
# Filenames key on the sender's reverse-DNS name; each line is stamped
# with wall-clock arrival time (the payload carries only the extended
# netconsole level,seq,monotonic-ts prefix, preserved for gap detection).
template(name="KernelLine" type="string"
         string="%timegenerated:::date-rfc3339% %rawmsg:::drop-last-lf%\\n")
"""
```

**(c)** Add `_kernel_block()` after `_net_block()`:

```python
def _kernel_block(net: str, addr: str) -> str:
    """Netconsole template + ruleset + leg-bound :6666 input for one net."""
    return f"""\
template(name="KernelLog-{net}" type="string"
         string="/var/log/{net}/%fromhost:::secpath-replace%.kernel.log")
ruleset(name="remote-{net}-kernel") {{
    action(type="omfile" dynaFile="KernelLog-{net}" template="KernelLine"
           fileOwner="root" fileGroup="adm"
           fileCreateMode="0640" dirCreateMode="0755")
    stop
}}
input(type="imudp" port="6666" address="{addr}" ruleset="remote-{net}-kernel")
"""
```

**(d)** In `generate_rsyslog()`, replace the single-line comprehension

```python
    parts.extend(_net_block(net, legs[net]) for net in sorted(legs))
```

with an interleaved loop (syslog block then kernel block per net, so each net's config reads as one unit):

```python
    for net in sorted(legs):
        parts.append(_net_block(net, legs[net]))
        parts.append(_kernel_block(net, legs[net]))
```

- [ ] **Step 4: Run the full test file to verify everything passes**

Run: `cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog && uv run pytest tests/test_generators/test_rsyslog.py -v`

Expected: ALL tests PASS (including the pre-existing ones — pay attention to `test_tmp_and_guest_excluded` and `test_no_leg_no_input`, which must still hold with the kernel blocks present).

- [ ] **Step 5: Commit**

```bash
cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog
git add src/gdoc2netcfg/generators/rsyslog.py tests/test_generators/test_rsyslog.py
git commit -m "feat: receive kernel netconsole per leg into <net>/<sender>.kernel.log

One leg-bound imudp input per served net on UDP 6666, ruleset-isolated
like the syslog inputs. Netconsole payloads are raw printk (no syslog
header, no hostname), so the dynafile keys on the sender's reverse-DNS
name and the shared KernelLine template stamps wall-clock arrival next
to the raw payload. Receive-only: pucks keep streaming to wisp:6666
until a documented follow-up re-points them.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BSHiudkQxHncLaoZeKPMDt"
```

---

### Task 2: Logrotate glob-coverage pin

The spec requires that logrotate emission be BYTE-IDENTICAL to the pre-change output — the existing `/var/log/<net>/*.log` globs already match `*.kernel.log`, so the same 1-year-floor policy applies for free. This task pins that so nobody later "fixes" the glob into excluding kernel files or adds redundant kernel stanzas. The test is expected to pass immediately (it pins current behaviour; Task 1 must not have touched `_logrotate()` or `_LOGROTATE_HEADER`).

**Files:**
- Test: `tests/test_generators/test_rsyslog.py`

- [ ] **Step 1: Write the pin test**

Append to `TestLogrotate`:

```python
    def test_logrotate_untouched_by_netconsole(self):
        # The /var/log/<net>/*.log globs already match *.kernel.log — the
        # kernel files ride the same 1-year-floor stanzas. Pin: no
        # kernel-specific stanza, and exactly one glob per served net.
        rot = generate_rsyslog(_default_inventory())["logrotate.d/remote-logs"]
        assert "kernel" not in rot
        assert rot.count("/var/log/") == 3
        for net in ("wifi", "net", "iot"):
            assert rot.count(f"/var/log/{net}/*.log {{") == 1
```

- [ ] **Step 2: Run it — expected to PASS immediately**

Run: `cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog && uv run pytest tests/test_generators/test_rsyslog.py::TestLogrotate -v`

Expected: PASS. If `test_logrotate_untouched_by_netconsole` FAILS, Task 1 leaked into the logrotate path — fix the generator, not the test.

- [ ] **Step 3: Commit**

```bash
cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog
git add tests/test_generators/test_rsyslog.py
git commit -m "test: pin logrotate output untouched by netconsole capture

The per-net *.log globs already cover *.kernel.log; guard against a
future 'fix' that excludes kernel files or duplicates stanzas.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BSHiudkQxHncLaoZeKPMDt"
```

---

### Task 3: Docs, acceptance sweep, push, PR update

**Files:**
- Modify: `CLAUDE.md` (the worktree's copy — same file PR #24 already touches)

- [ ] **Step 1: Add the netconsole paragraph to CLAUDE.md**

Locate the `### Per-net remote syslog` section (added by the earlier syslog work — `grep -n "Per-net remote syslog" CLAUDE.md`). Two edits:

**(a)** That section contains the sentence "Kernel netconsole is separate and unchanged: crash forensics stays on wisp:6666 (`netconsole_rx`), now unpolluted by device syslog." — now stale (ten64 *does* receive netconsole, even if nothing sends yet). Replace that sentence with: "Kernel netconsole's **sender side** is unchanged: the pucks still stream to wisp:6666 (`netconsole_rx`), now unpolluted by device syslog."

**(b)** Append this paragraph at the END of the section, immediately before the next `###` heading:

```markdown
The same drop-in also receives **kernel netconsole** (raw printk, no
syslog header): one leg-bound input per served net on UDP 6666 into
`/var/log/<net>/<sender>.kernel.log`, filename keyed on the sender's
reverse-DNS name, each line stamped with wall-clock arrival ahead of the
raw payload (the extended-netconsole `level,seq,ts,-;` prefix survives,
so message drops show as sequence gaps). The per-net logrotate globs
(`*.log`) cover these files — no extra stanzas. Receive-only today: the
gale pucks still stream netconsole to wisp:6666 (`gwifi-netconsole.service`);
re-pointing them at a ten64 leg and retiring the wisp receiver is a
documented follow-up (gwifi-openwrt image + live push), like the 10514
transition input.
```

- [ ] **Step 2: Full acceptance sweep**

```bash
cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog
uv run pytest -q
uv run ruff check src/ tests/
```

Expected: full suite passes (2174+ tests, now +6), ruff clean.

- [ ] **Step 3: Commit the docs change**

```bash
cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog
git add CLAUDE.md
git commit -m "docs: document kernel netconsole receive in the syslog section

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01BSHiudkQxHncLaoZeKPMDt"
```

- [ ] **Step 4: Push and update PR #24**

```bash
cd /home/tim/local/gwifi/gdoc2netcfg/.worktrees/wifi-syslog
git push origin wifi-syslog
```

Then append a "Netconsole receive" section to the PR #24 body (use `gh pr view 24 --json body -q .body` to fetch, edit, `gh pr edit 24 --body-file -` or a temp file under the repo's `tmp/`, cleaned up after): one short paragraph — per-leg UDP 6666 inputs → `/var/log/<net>/<sender>.kernel.log`, fromhost-keyed, arrival-stamped rawmsg, receive-only (pucks still → wisp:6666), logrotate covered by the existing globs, spec `docs/superpowers/specs/2026-07-31-netconsole-receive-design.md`.

Verify CI goes green: `gh pr checks 24 --watch` (lint + 3.11/3.12/3.13).

---

## Phase 2 rollout additions (controller-run, NOT for subagents)

These extend the existing rollout runbook in `2026-07-30-per-net-remote-syslog.md` — same deploy step (`sudo make deploy-syslog` ships the same `remote-logs.conf`), so netconsole receive deploys for free with the syslog rollout. Additional live checks per site:

1. `ss -ulpn | grep 6666` — one listener per served leg (welland 8, monarto 7), plus wisp's own 10.1.4.2:6666 remains untouched (different host).
2. Probe from a leaf host: `printf '6,1,0,-;netconsole rx test\n' | nc -u -w1 <leg-ip> 6666` → lands in `/var/log/<net>/<sender>.kernel.log`.
3. **Assert the filename uses the SHORT hostname** (e.g. `puck07.kernel.log`, not `puck07.wifi.welland.mithis.com.kernel.log` and not a bare IP) — this validates rsyslog's `preserveFQDN` default + PTR coverage, which unit tests cannot pin. A long-form or IP filename means reverse DNS or rsyslog global config needs attention.
4. `/var/log/syslog` gains nothing from the probe (stop-isolation).

Documented follow-up (out of scope, tracked in memory): re-point the pucks' `gale-netconsole` init script (gale image + live push) at the site wifi leg and retire wisp's `gwifi-netconsole.service`.
