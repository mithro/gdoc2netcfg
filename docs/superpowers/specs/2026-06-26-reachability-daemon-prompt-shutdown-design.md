# Reachability Daemon Prompt Shutdown — Design

**Task:** #12 — Make the reachability daemon shut down promptly on SIGTERM
(stalls ~90s mid-startup).

**Goal:** A `systemctl restart` (or stop) of `gdoc2netcfg-reachability.service`
exits the old daemon instance in **under 5 seconds at any phase** (startup,
mid-sweep, idle wait) **with no traceback**.

## Problem

The daemon (`run_daemon` in `src/gdoc2netcfg/supplements/mqtt_ha.py`) runs an
infinite cycle: rebuild the host inventory, ping every host
(`check_all_hosts_reachability` in `src/gdoc2netcfg/supplements/reachability.py`),
save results to the DiscoveryDB, publish to MQTT, then sleep `interval`
seconds. Three defects make SIGTERM slow or crashy:

1. **Signal-unsafe handler** (`mqtt_ha.py:806-811`). `signal_handler` calls
   `print(..., file=sys.stderr)` *before* `stop_event.set()`. A signal handler
   runs on the main thread between bytecodes; if the main thread is mid-write to
   the stderr buffer when the signal lands, the handler re-enters the buffer
   lock and raises `RuntimeError: reentrant call inside
   <_io.BufferedWriter name='<stderr>'>`. Because the failing `print` is *before*
   `set()`, a crash there means **`stop_event` is never set**. (Observed on
   welland during the #7 deploy restart.)

2. **The sweep cannot be interrupted** (`reachability.py:380-451`).
   `check_all_hosts_reachability` holds no reference to `stop_event`. It submits
   every host's pings to a `ThreadPoolExecutor(max_workers=64)` inside a `with`
   block, then blocks on each `future.result()`. The `with` block's exit calls
   `shutdown(wait=True)`, which waits for every submitted ping. Each unreachable
   host's ping is `ping -c 10 -W 1` ≈ ~10s; with 200+ hosts batched 64 at a
   time, a full sweep is the ~90s stall. A SIGTERM mid-sweep cannot shorten it.

3. **Fixed sleep in publish + unbounded teardown.** `_publish_hosts_to_client`
   has a fixed `time.sleep(2)` between its discovery and state phases
   (`mqtt_ha.py:656`). The `finally` teardown (`disconnect()` → `loop_stop()`)
   has no stop awareness.

## Key insight: systemd reaps the ping children

`systemctl restart` uses the default `KillMode=control-group`, so systemd sends
SIGTERM to **every** process in the unit's cgroup — including the in-flight
`ping` subprocesses. `ping` exits on SIGTERM. So under systemd the pings are
already terminated for us; the daemon only has to (a) not crash in its handler
and (b) stop *blocking* on the now-dead pings. This is why **cooperative abort**
(observe a stop flag, don't manage the subprocesses ourselves) is sufficient and
is the chosen approach.

## Design: cooperative abort

A single `threading.Event` (the existing `stop_event`) is the shared abort
signal. Every long-blocking step in a cycle observes it.

### 1. Async-signal-safe handler (`run_daemon`)

The handler does the minimum work that is safe from signal context: record the
signal number and set the event. It writes nothing.

```python
stop_event = threading.Event()
caught: dict[str, int] = {}

def signal_handler(signum, frame):
    caught["signum"] = signum   # main-thread, between-bytecodes — safe
    stop_event.set()            # Event.set() is safe from a handler

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
```

The shutdown message moves to the main loop, printed *after* the loop observes
the event:

```python
if stop_event.is_set():
    signum = caught.get("signum")
    if verbose:
        print(f"\nReceived signal {signum}, shutting down...", file=sys.stderr)
```

Eliminating the print from signal context removes the reentrancy crash, and
`set()` always runs.

### 2. Interruptible sweep (`check_all_hosts_reachability`)

Add an optional `stop_event: threading.Event | None = None` parameter. When the
event is set, the sweep stops promptly and returns whatever it has collected so
far (a partial mapping):

- The result-collection loop checks `stop_event.is_set()` at the top of each
  host iteration and **breaks** instead of blocking on the remaining
  `future.result()` calls.
- The `with ThreadPoolExecutor(...) as pool:` is replaced with an explicit
  `pool = ThreadPoolExecutor(...)` guarded by `try/finally`. On normal
  completion the pool is shut down with `pool.shutdown(wait=True)`; when aborting
  it is shut down with `pool.shutdown(wait=False, cancel_futures=True)` so queued
  pings are cancelled and we do not block draining in-flight ones (systemd has
  already SIGTERM'd them).

When `stop_event` is `None` (the CLI one-shot `reachability publish --force`
path and existing callers) behaviour is unchanged.

### 3. Discard an aborted cycle (`run_daemon`)

A partial sweep is **not** real data. `_save_reachability_to_db` tombstones
hosts absent from the result, so saving a half-finished sweep would tombstone
every not-yet-pinged host and publish them as false-unreachable. The loop must
therefore check the event and break **before** saving or publishing:

```python
hosts = _rebuild_hosts(config, hosts, cycle)
if stop_event.is_set():
    break

reachability = check_all_hosts_reachability(hosts, verbose=verbose, stop_event=stop_event)
if stop_event.is_set():
    break   # aborted mid-sweep — discard the partial result, save/publish nothing

_save_reachability_to_db(config, reachability)
... publish ...
stop_event.wait(timeout=interval)
```

The idle `stop_event.wait(timeout=interval)` is already interruptible.

### 4. Bounded publish + teardown

- `_publish_hosts_to_client` takes the `stop_event` and replaces its fixed
  `time.sleep(2)` with `stop_event.wait(2)` so a SIGTERM during publish does not
  burn the full 2s.
- The `finally` teardown order (`publish offline` → `disconnect()` →
  `loop_stop()`) is already correct and bounded — the paho network thread exits
  promptly after `disconnect()`. Left unchanged.

## Out of scope (YAGNI)

- **Killing ping subprocesses ourselves.** systemd's cgroup SIGTERM reaps them;
  the acceptance criterion is specifically `systemctl restart`. (A signal
  delivered to *only* the main process — manual `kill <pid>`, a debugger — would
  leave in-flight pings to self-terminate at ~10s; not in scope.)
- **Interruptible startup `client.connect()`.** The unit is ordered
  `After=mosquitto.service`, and PEP 475 auto-resumes the syscall across a
  signal anyway. A separate concern if a down broker ever makes connect block.

## Testing

All tests use the existing patterns (`@patch(...reachability.subprocess.run)`,
the `_host()` fixture builder, `patch(...cli.main._build_pipeline)`).

1. **Sweep abort** (`tests/test_supplements/test_reachability.py`): patch
   `check_reachable` to block on an unset `threading.Event`; pass a
   **pre-set** `stop_event` to `check_all_hosts_reachability`; assert it returns
   in well under a second and did not collect every host (i.e. did not block on
   the slow pings).
2. **Signal handler** (`tests/test_supplements/test_mqtt_ha_daemon.py`): build
   the handler, call it with a signum, assert `stop_event` is set, the signum is
   recorded, and **nothing** was written to stderr (`capsys`).
3. **Aborted-cycle discard / integration**
   (`tests/test_supplements/test_mqtt_ha_daemon.py`): run `run_daemon` with a
   mocked `mqtt.Client` and monkeypatched `_rebuild_hosts` + sweep; set the
   event from a helper thread (or have the patched sweep set it); assert
   `run_daemon` returns promptly and `_save_reachability_to_db` was **not**
   called for the aborted cycle.

## Acceptance

`systemctl restart gdoc2netcfg-reachability.service` at any phase exits the old
instance in under 5 seconds with no traceback, verified on both welland and
monarto after deploy.
