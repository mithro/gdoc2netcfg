# Netconsole Receive Design

**Date:** 2026-07-31
**Status:** Approved (user-reviewed brainstorm; this document records the design)
**Repo:** `gdoc2netcfg` (receive side only — extends the per-net remote
syslog work, see `2026-07-30-per-net-remote-syslog-design.md`)

## Problem

The gale pucks stream kernel printk (including panic traces) over UDP
netconsole because they have no accessible serial console in the field.
Today the only receiver is `gwifi-netconsole.service` on wisp
(10.1.4.2:6666, `netconsole_rx.py`): per-**source-IP** files under
`/var/log/gale-netconsole/`, no hostname keying, no rotation, and
welland-only. The new per-net remote syslog stack on the ten64s handles
device *syslog* but deliberately left netconsole out of scope.

Netconsole datagrams are raw printk lines, not syslog: no PRI header, no
hostname, no wall-clock timestamp (the extended format carries
`level,seq,monotonic-ts,-;` prefixes only). They therefore cannot share
the syslog rulesets — the hostname must come from the *sender*, and the
arrival time must be stamped by the receiver.

## Design decisions (user-approved)

1. **Receive-only for now.** ten64 gains netconsole inputs; no puck-side
   change ships with this work. The pucks keep streaming to wisp:6666,
   and wisp's receiver stays. Nothing arrives at ten64 until a later
   re-point (documented follow-up, like the 10514 transition input).
2. **Every served leg listens** — the same net set as the syslog inputs
   (all leaf legs except tmp/guest), port **6666** on each leg address.
   6666 matches the fleet convention, so the eventual re-point is a
   target-IP change only.
3. **Files land next to the syslog files** with a distinct suffix:
   `/var/log/<net>/<hostname>.kernel.log` (e.g. `wifi/puck07.kernel.log`
   beside `wifi/puck07.log`).

## Generator change

`src/gdoc2netcfg/generators/rsyslog.py` (on the `wifi-syslog` branch —
the generator only exists there; PR #24 grows by these commits). Emitted
into the same `etc/rsyslog.d/remote-logs.conf`:

- **Once, in the header area** — the shared line template:

  ```
  template(name="KernelLine" type="string"
           string="%timegenerated:::date-rfc3339% %rawmsg:::drop-last-lf%\n")
  ```

- **Per served net** (alongside the existing syslog block):

  ```
  template(name="KernelLog-<net>" type="string"
           string="/var/log/<net>/%fromhost:::secpath-replace%.kernel.log")
  ruleset(name="remote-<net>-kernel") {
      action(type="omfile" dynaFile="KernelLog-<net>" template="KernelLine"
             fileOwner="root" fileGroup="adm"
             fileCreateMode="0640" dirCreateMode="0755")
      stop
  }
  input(type="imudp" port="6666" address="<leg-v4>" ruleset="remote-<net>-kernel")
  ```

Three properties differ from the syslog blocks, all forced by the
payload shape:

- **Filename keys on a short name extracted from `%fromhost%`** — the
  sender's reverse-DNS name (the payload has no hostname).

  > **Corrected 2026-08-01 after live rollout.** This section originally
  > claimed rsyslog's default `preserveFQDN=off` would shorten
  > `puck07.wifi.welland.mithis.com` to `puck07`. It does not: the first
  > deployment produced
  > `/var/log/wifi/ipv4.wisp.wifi.welland.mithis.com.kernel.log`. Worse,
  > this estate's PTRs are **ipv4-prefixed**, so naive first-label
  > truncation would yield a useless `ipv4`. The extraction below replaces
  > that assumption.

  The ruleset extracts the first real label with
  `re_extract($fromhost, "^(ipv4[.]|ipv6[.])?([a-zA-Z][a-zA-Z0-9-]*)[.]",
  0, 2, "")`, falling back to the full `$fromhost` when the regex misses,
  so `wisp.kernel.log` sits beside `wisp.log`. The explicit fallback is
  required: rsyslog's own no-match modes are unusable here — `DFLT`
  substitutes the literal string `**NO MATCH**`, which would collapse
  every PTR-less sender into one shared file. With the fallback, a sender
  with no PTR keeps its bare IP (`10.1.4.99.kernel.log`) — degraded but
  distinct and never lost. `secpath-replace` still guards the path,
  covering the fallback branch where a broken or hostile PTR lands
  verbatim.

  All of the above was verified against live rsyslog 8.2606 in a sandbox
  before deployment (short-name, no-prefix, router-leg, bare-IP,
  single-label and path-traversal cases).
- **Line template = arrival timestamp + `%rawmsg%`** — the receiver
  stamps wall-clock arrival (RFC 3339), same job the wisp receiver does
  today; `rawmsg` preserves the extended-netconsole prefix
  (`level,seq,ts,-;`) untouched, which is what lets a reader detect
  dropped messages by sequence gap. `drop-last-lf` prevents blank lines
  when a datagram carries its own trailing newline (belt-and-braces —
  rsyslog also drops a trailing LF at reception by default).
- **Port 6666**, leg-bound like the 514 inputs.

Everything else is carried over unchanged from the syslog blocks:
ruleset isolation + `stop` (kernel lines never reach `/var/log/syslog`),
`omfile` ownership/modes, dynafile dir auto-creation, v4-only legs, the
fail-loud legs derivation.

**Logrotate: no change.** The existing per-net stanzas glob
`/var/log/<net>/*.log`, which matches `*.kernel.log` — the same
1-year-floor policy applies for free. A test pins this so the glob is
never "fixed" into excluding the kernel files.

## Out of scope (documented follow-ups)

- Re-pointing the pucks' `gale-netconsole` init script (gale image +
  live push) at a ten64 leg, and retiring wisp's
  `gwifi-netconsole.service` — a later gwifi-openwrt task.
- Any change to the syslog (514/10514) inputs.

## Testing

Extend `tests/test_generators/test_rsyslog.py` (TDD):

- Per served net: `KernelLog-<net>` template with
  `%fromhost:::secpath-replace%` and the `.kernel.log` suffix;
  `remote-<net>-kernel` ruleset with `stop`; a port-6666 input bound to
  that net's leg address and that ruleset.
- The `KernelLine` template appears exactly once and contains
  `%timegenerated:::date-rfc3339%` and `%rawmsg:::drop-last-lf%`.
- tmp/guest still excluded (no 6666 input for them).
- The logrotate output is byte-identical to the pre-change output
  (glob-coverage pin).
- Full suite + ruff.

**Live verification (per site, at rollout):** `ss -ulpn` shows a 6666
listener per served leg; a manual probe from a leaf host
(`printf '6,1,0,-;netconsole rx test\n' | nc -u -w1 <leg> 6666`) lands
in `/var/log/<net>/<sender-host>.kernel.log` with an arrival timestamp
and the raw payload; `/var/log/syslog` gains nothing.

## Alternatives considered

- **Port the Python `netconsole_rx` receiver to ten64** as a systemd
  service: rejected — a second daemon, hand-rolled rotation/ownership,
  duplicating what rsyslog does natively. The wisp receiver only exists
  because wisp predates this rsyslog work.
- **Single wildcard 6666 input into one shared dir**: rejected — loses
  the per-net classification the whole design is built on.
- **Separate tree (`/var/log/netconsole/<net>/`) or sibling dirs
  (`/var/log/<net>-netconsole/`)**: rejected by user — splits a device's
  logs across trees and needs its own logrotate stanzas; the
  `.kernel.log` suffix keeps streams separate at the file level.
