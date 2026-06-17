# Support `proxy` Sensors classification — Design

**Date:** 2026-06-17
**Task:** #41
**Status:** Approved design → implementation plan

## Problem

The Network sheet's `Sensors` column classifies each host for sensors2mqtt:
`local` (runs a collector locally, gets an HA broker login), `remote` (polled by a
collector elsewhere), or blank (not involved). The operator has introduced a 4th
value, `proxy`, for the 21 `pi*.fpgas` lab Pis: these run sensors2mqtt but publish
to a *different* MQTT broker (tweed), whose data is proxied onto the HA broker. A
`proxy` host therefore needs **no HA broker login of its own**, but its state
**should still be checked** on HA.

`classify()` in `src/gdoc2netcfg/derivations/sensors2mqtt.py` only accepts
`local`/`remote`/blank and **fails loud** on `proxy`. Because `sensors2mqtt
list`/`register`/`status` and `build_logins` all classify every host, a single
`proxy` value currently breaks all of them:
`ValueError: host pi1.fpgas: unrecognized Sensors value 'proxy'`.
Live `Sensors` counts: 129 blank, 43 local, 22 remote, 21 proxy (all fpgas).

## Goal

Accept `proxy` in the `Sensors` column with these semantics:
- **No HA broker login** (the host uses its own broker) — excluded from `build_logins`.
- **Included in the HA state check** (its data is proxied onto HA).

## Design

A single change in `src/gdoc2netcfg/derivations/sensors2mqtt.py`:

- Add `"proxy"` to `classify()`'s `_VALID` set so `classify()` returns `"proxy"`
  instead of raising. Update the docstring/error message to list `proxy`.

No change is needed to the selectors — they already produce the desired behaviour
once `classify` accepts the value:

- `select_local` = `classify == "local"` → **excludes** `proxy` → no `s2m-` login
  is built or registered for it. ✓
- `select_non_blank` = `classify != "blank"` → **includes** `proxy` → it is part of
  the host set the `status` command checks. ✓

`proxy` is kept **distinct** from `remote` (not aliased to it): they behave
identically for the current selectors, but the semantics differ (`remote` = polled
by another collector; `proxy` = self-publishes to another broker), so keeping the
distinct label preserves that meaning for future code.

## Out of scope (tracked as #42)

This change makes `proxy` hosts *selected* for the status check; it does **not**
make the status check correctly *find* their HA entities. Verification against the
live broker (2026-06-17) showed the status check matches ids derived from
`node_id(host.hostname)` (e.g. `sensor.pi1_fpgas_*`), whereas sensors2mqtt actually
publishes under the bare/OS hostname (`sensor.pi1_*`). That mismatch affects **all
subdomain hosts** — the `proxy` `.fpgas` Pis *and* the local `.iot` Pis — and is a
pre-existing bug tracked as **#42**. **The fix for #42 is to be explored separately
and is deliberately not decided or specified here.** This spec neither fixes nor
depends on that fix; it only ensures `proxy` hosts are classified and selected
correctly.

## Testing

In `tests/test_derivations/test_sensors2mqtt.py`:
- `classify()` returns `"proxy"` for a host with `Sensors="proxy"` (case-insensitive,
  stripped), and still raises `ValueError` on a genuinely unknown value.
- `select_local` (and `build_logins`) **exclude** a `proxy` host (no login built).
- `select_non_blank` **includes** a `proxy` host.

## Files

- Modify: `src/gdoc2netcfg/derivations/sensors2mqtt.py` (classify `_VALID` + docstring/error)
- Test: `tests/test_derivations/test_sensors2mqtt.py`
