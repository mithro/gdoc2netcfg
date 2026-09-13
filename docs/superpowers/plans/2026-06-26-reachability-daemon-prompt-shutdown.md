# Reachability Daemon Prompt Shutdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `gdoc2netcfg-reachability.service` exit in under 5 seconds on SIGTERM at any phase (startup, mid-sweep, idle wait) with no traceback.

**Architecture:** Cooperative abort around the daemon's existing `threading.Event` (`stop_event`). The signal handler becomes async-signal-safe (records the signum + sets the event, no I/O); the ping sweep gains an optional `stop_event` it polls so it can return early; the daemon loop discards an aborted cycle instead of saving a partial sweep. systemd's `KillMode=control-group` SIGTERM reaps the in-flight `ping` children, so the daemon never manages the subprocesses itself.

**Tech Stack:** Python 3.11–3.13, `threading`, `concurrent.futures.ThreadPoolExecutor`, `paho-mqtt`, pytest with `unittest.mock`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-26-reachability-daemon-prompt-shutdown-design.md`.
- The signal handler must write **nothing** (no `print`/stderr) — it records the signum and calls `stop_event.set()` only. The shutdown message is printed by the main loop after it observes the event.
- An aborted cycle (stop seen after the sweep) must **not** call `_save_reachability_to_db` or `_publish_hosts_to_client` — a partial sweep would tombstone not-yet-pinged hosts as false-unreachable (project rule: never fabricate / never silently discard data).
- `check_all_hosts_reachability`'s new `stop_event` parameter defaults to `None` and, when `None`, leaves existing behaviour byte-for-byte unchanged (the CLI one-shot path in `cli/main.py:840` passes no `stop_event`).
- `_publish_hosts_to_client`'s new `stop_event` parameter defaults to `None`; the `--force` one-shot caller (`mqtt_ha.py:731`) passes no `stop_event` and must keep using `time.sleep(2)`.
- Out of scope (do not implement): killing ping subprocesses ourselves; making startup `client.connect()` interruptible.
- Run tests with `uv run pytest` (never bare `python`/`pytest`).

---

### Task 1: Interruptible ping sweep

Add an optional `stop_event` to `check_all_hosts_reachability` so a set event makes it stop collecting and tear the thread pool down without blocking on in-flight pings.

**Files:**
- Modify: `src/gdoc2netcfg/supplements/reachability.py` (imports near line 7–16; function `check_all_hosts_reachability` at lines 380–490)
- Test: `tests/test_supplements/test_reachability.py` (add to `class TestCheckAllHostsReachability`, after line 255)

**Interfaces:**
- Produces: `check_all_hosts_reachability(hosts: list[Host], verbose: bool = False, max_workers: int = 64, stop_event: threading.Event | None = None) -> dict[str, HostReachability]`. When `stop_event` is set, returns the hosts collected so far (a partial dict — possibly empty) and does not block on the remaining pings.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_supplements/test_reachability.py`. Put `import threading` and `import time` at the top of the file if not already present (the file currently imports neither). Add this test method inside `class TestCheckAllHostsReachability`:

```python
    @patch("gdoc2netcfg.supplements.reachability.check_reachable")
    def test_aborts_promptly_when_stop_event_set(self, mock_reachable):
        """A set stop_event makes the sweep return without blocking on pings."""
        release = threading.Event()

        def slow_ping(ip):
            # Mimic a slow unreachable host. If the sweep collected this
            # result it would block here; the abort path must not wait on it.
            release.wait(timeout=5)
            return False

        mock_reachable.side_effect = slow_ping

        stop = threading.Event()
        stop.set()
        hosts = [_make_host(f"h{i}", f"10.1.10.{i}") for i in range(1, 8)]

        start = time.monotonic()
        result = check_all_hosts_reachability(hosts, stop_event=stop)
        elapsed = time.monotonic() - start
        release.set()  # unblock any worker threads so the pool can drain

        assert elapsed < 1.0
        assert len(result) < len(hosts)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_supplements/test_reachability.py::TestCheckAllHostsReachability::test_aborts_promptly_when_stop_event_set -v`
Expected: FAIL — `TypeError: check_all_hosts_reachability() got an unexpected keyword argument 'stop_event'`.

- [ ] **Step 3: Add the `threading` type-only import**

In `src/gdoc2netcfg/supplements/reachability.py`, the file already has (lines 14–16):

```python
if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
```

Add `threading` to that block so the new annotation resolves for type-checkers (the file uses `from __future__ import annotations`, so the annotation is a string at runtime and `threading` is never referenced at runtime):

```python
if TYPE_CHECKING:
    import threading

    from gdoc2netcfg.models.host import Host
```

- [ ] **Step 4: Add the `stop_event` parameter**

Change the signature of `check_all_hosts_reachability` (currently lines 380–384) to:

```python
def check_all_hosts_reachability(
    hosts: list[Host],
    verbose: bool = False,
    max_workers: int = 64,
    stop_event: threading.Event | None = None,
) -> dict[str, HostReachability]:
```

Update the docstring's `Args:` block to add:

```
        stop_event: If set during the sweep, stop collecting results and
            return what has been gathered so far without blocking on the
            remaining pings.
```

- [ ] **Step 5: Make the collection loop and pool teardown observe the event**

Replace the `with ThreadPoolExecutor(max_workers=max_workers) as pool:` block (currently line 431) and everything indented under it (through line 485) with an explicit pool managed by `try/finally`. The submit loop and collection loop bodies are unchanged except for the new abort check at the top of the collection loop. Concretely, lines 431–485 become:

```python
    pool = ThreadPoolExecutor(max_workers=max_workers)
    aborted = False
    try:
        # Submit all pings up front, deduplicating IPs across interfaces.
        host_futures: list[
            tuple[Host, list[tuple[int, str, Future[PingResult]]]]
        ] = []
        for host in sorted_hosts:
            ip_futures: list[tuple[int, str, Future[PingResult]]] = []
            seen_ips: set[str] = set()
            for vi_idx, vi in enumerate(host.virtual_interfaces):
                for ip_str in vi.all_ips:
                    if ip_str in seen_ips:
                        continue
                    seen_ips.add(ip_str)
                    future = pool.submit(check_reachable, ip_str)
                    ip_futures.append((vi_idx, ip_str, future))
            host_futures.append((host, ip_futures))

        # Collect results in sorted order — blocks on each host's futures
        # while remaining hosts continue pinging in the background.
        # Prints each host as soon as its pings complete.
        for host, ip_futures in host_futures:
            if stop_event is not None and stop_event.is_set():
                aborted = True
                break

            active_ips: list[str] = []
            vi_count = len(host.virtual_interfaces)
            iface_pings: list[list[tuple[str, PingResult]]] = [
                [] for _ in range(vi_count)
            ]

            for vi_idx, ip_str, future in ip_futures:
                ping = future.result()
                iface_pings[vi_idx].append((ip_str, ping))
                if ping:
                    active_ips.append(ip_str)

            iface_reachability = tuple(
                InterfaceReachability(pings=tuple(pings))
                for pings in iface_pings
            )

            hr = HostReachability(
                hostname=host.hostname,
                active_ips=tuple(active_ips),
                interfaces=iface_reachability,
            )
            result[host.hostname] = hr

            # Print this host immediately.
            if verbose:
                _print_host_reachability(
                    hr,
                    name_width=name_width,
                    ip_width=ip_width,
                    cols=cols,
                    prefix=prefix,
                    use_color=color,
                )
    finally:
        # On abort, cancel queued pings and don't block draining the
        # in-flight ones — systemd's cgroup SIGTERM reaps the ping children.
        pool.shutdown(wait=not aborted, cancel_futures=aborted)
```

Leave the trailing `if verbose: print(file=sys.stderr)` and `return result` (lines 487–490) exactly as they are, after the `finally`.

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/test_supplements/test_reachability.py -v`
Expected: PASS (the new test plus all existing `TestCheckAllHostsReachability` tests).

- [ ] **Step 7: Commit**

```bash
git add src/gdoc2netcfg/supplements/reachability.py tests/test_supplements/test_reachability.py
git commit -m "feat: make check_all_hosts_reachability abortable via stop_event (#12)"
```

---

### Task 2: Daemon honours the stop event

Make `run_daemon` use an async-signal-safe handler, pass the event into the sweep, discard an aborted cycle (no save/publish), print the shutdown message from the loop, and make the publish 2-second wait abortable.

**Files:**
- Modify: `src/gdoc2netcfg/supplements/mqtt_ha.py` (`_publish_hosts_to_client` at 550–567 + its `time.sleep(2)` at 656; add `_make_signal_handler` near `run_daemon`; `run_daemon` body at 804–888)
- Test: `tests/test_supplements/test_mqtt_ha_daemon.py` (append two tests)

**Interfaces:**
- Consumes (from Task 1): `check_all_hosts_reachability(hosts, verbose=..., stop_event=...)`.
- Produces: `_make_signal_handler(stop_event: threading.Event, caught: dict[str, int]) -> Callable[[int, FrameType | None], None]` (module-level, importable for tests). `_publish_hosts_to_client(..., stop_event: threading.Event | None = None)`.

- [ ] **Step 1: Write the failing handler test**

Append to `tests/test_supplements/test_mqtt_ha_daemon.py`:

```python
def test_signal_handler_sets_event_records_signum_silently(capsys):
    import signal
    import threading

    from gdoc2netcfg.supplements.mqtt_ha import _make_signal_handler

    stop = threading.Event()
    caught: dict[str, int] = {}
    handler = _make_signal_handler(stop, caught)

    handler(signal.SIGTERM, None)

    assert stop.is_set()
    assert caught["signum"] == signal.SIGTERM
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == ""
```

- [ ] **Step 2: Write the failing aborted-cycle test**

Append to `tests/test_supplements/test_mqtt_ha_daemon.py`:

```python
def test_aborted_cycle_does_not_save_or_publish():
    from unittest.mock import MagicMock, patch

    from gdoc2netcfg.supplements.mqtt_ha import run_daemon

    cfg = _config()

    def fake_sweep(hosts, verbose=False, stop_event=None):
        # Simulate SIGTERM landing mid-sweep.
        stop_event.set()
        return {}

    with patch(
        "gdoc2netcfg.supplements.mqtt_ha.mqtt.Client"
    ) as mock_client_cls, patch(
        "gdoc2netcfg.storage.open_databases"
    ) as mock_opendb, patch(
        "gdoc2netcfg.supplements.mqtt_ha._rebuild_hosts", return_value=["h1"]
    ), patch(
        "gdoc2netcfg.supplements.reachability.check_all_hosts_reachability",
        side_effect=fake_sweep,
    ), patch(
        "gdoc2netcfg.cli.main._save_reachability_to_db"
    ) as mock_save, patch(
        "gdoc2netcfg.supplements.mqtt_ha._publish_hosts_to_client"
    ) as mock_publish:
        mock_client_cls.return_value = MagicMock()
        mock_opendb.return_value = MagicMock()
        run_daemon(cfg, interval=300, verbose=False)

    mock_save.assert_not_called()
    mock_publish.assert_not_called()
```

- [ ] **Step 3: Run both tests to verify they fail**

Run: `uv run pytest tests/test_supplements/test_mqtt_ha_daemon.py -v`
Expected: FAIL — `test_signal_handler...` fails with `ImportError: cannot import name '_make_signal_handler'`; `test_aborted_cycle...` errors (`run_daemon` calls the sweep without `stop_event`, so `fake_sweep` hits `stop_event.set()` on `None`) or fails `assert_not_called`.

- [ ] **Step 4: Add the signal-handler factory**

In `src/gdoc2netcfg/supplements/mqtt_ha.py`, add this module-level function immediately above `def run_daemon(` (currently line 781):

```python
def _make_signal_handler(
    stop_event: threading.Event, caught: dict[str, int]
):
    """Build an async-signal-safe SIGTERM/SIGINT handler.

    A signal handler runs on the main thread between bytecodes; doing
    anything that could re-enter a lock the main thread already holds (such
    as writing to the buffered stderr) raises ``RuntimeError: reentrant
    call inside <_io.BufferedWriter>``. So the handler does the minimum:
    record the signal number and set the stop event. The shutdown message
    is printed by the main loop once it observes the event.
    """

    def signal_handler(signum, frame):
        caught["signum"] = signum
        stop_event.set()

    return signal_handler
```

- [ ] **Step 5: Wire the factory into `run_daemon`**

Replace the handler setup in `run_daemon` (currently lines 804–814):

```python
    stop_event = threading.Event()

    def signal_handler(signum, frame):
        print(
            f"\nReceived signal {signum}, shutting down...",
            file=sys.stderr,
        )
        stop_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
```

with:

```python
    stop_event = threading.Event()
    caught: dict[str, int] = {}
    handler = _make_signal_handler(stop_event, caught)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
```

- [ ] **Step 6: Add abort checks, pass the event to the sweep, and print the shutdown message from the loop**

Replace the `try:`/loop/`finally` block (currently lines 838–888) with:

```python
    try:
        hosts = None
        cycle = 0
        while not stop_event.is_set():
            cycle += 1
            if verbose:
                print(
                    f"\n--- Cycle {cycle} ---",
                    file=sys.stderr,
                )

            # Rebuild from the current cached CSVs + supplements each cycle so
            # host-list / supplement changes are picked up without a restart.
            hosts = _rebuild_hosts(config, hosts, cycle)
            if stop_event.is_set():
                break

            # Scan reachability
            reachability = check_all_hosts_reachability(
                hosts, verbose=verbose, stop_event=stop_event,
            )
            if stop_event.is_set():
                # Aborted mid-sweep: the partial result is not real data.
                # Saving it would tombstone not-yet-pinged hosts and publish
                # them as false-unreachable, so discard the whole cycle.
                break

            # Save to DiscoveryDB (delta-based historical storage),
            # tombstoning hosts that vanished from the inventory.
            from gdoc2netcfg.cli.main import _save_reachability_to_db

            _save_reachability_to_db(config, reachability)

            # Publish discovery + state using shared helper
            published, disc, state = _publish_hosts_to_client(
                client, hosts, reachability,
                verbose=verbose, stop_event=stop_event,
            )

            # Bridge online
            client.publish(BRIDGE_AVAIL_TOPIC, "online", retain=True)

            if verbose:
                print(
                    f"Published {disc} discovery + {state} state "
                    f"for {published} hosts. Next scan in {interval}s.",
                    file=sys.stderr,
                )

            stop_event.wait(timeout=interval)

        # The loop only exits once stop_event is set (handler-driven).
        if verbose:
            signum = caught.get("signum")
            print(
                f"\nReceived signal {signum}, shutting down...",
                file=sys.stderr,
            )

    finally:
        # Mark bridge offline on clean shutdown
        client.publish(BRIDGE_AVAIL_TOPIC, "offline", retain=True)
        client.disconnect()
        client.loop_stop()
        if verbose:
            print("MQTT daemon stopped.", file=sys.stderr)
```

- [ ] **Step 7: Make the publish 2-second wait abortable**

Change `_publish_hosts_to_client`'s signature (currently lines 550–555) to add the parameter:

```python
def _publish_hosts_to_client(
    client: mqtt.Client,
    hosts: list[Host],
    reachability: dict[str, HostReachability],
    verbose: bool = False,
    stop_event: threading.Event | None = None,
) -> tuple[int, int, int]:
```

Then replace the fixed sleep (currently line 656, `time.sleep(2)`) with:

```python
    # Wait for HA to process discovery and subscribe to state topics. Use
    # stop_event.wait so a shutdown signal doesn't burn the full 2 seconds.
    if stop_event is not None:
        stop_event.wait(2)
    else:
        time.sleep(2)
```

Leave the `import time` at the top of `_publish_hosts_to_client` (it is still used by the `else` branch) and the one-shot caller at line 731 unchanged (it passes no `stop_event`).

- [ ] **Step 8: Run the tests to verify they pass**

Run: `uv run pytest tests/test_supplements/test_mqtt_ha_daemon.py tests/test_supplements/test_mqtt_ha.py -v`
Expected: PASS (the two new tests plus all existing daemon and publish tests).

- [ ] **Step 9: Commit**

```bash
git add src/gdoc2netcfg/supplements/mqtt_ha.py tests/test_supplements/test_mqtt_ha_daemon.py
git commit -m "feat: reachability daemon honours stop_event for prompt SIGTERM shutdown (#12)"
```

---

### Task 3: Full suite + lint gate

Confirm the whole project is green and lint-clean before review.

**Files:** none (verification only).

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest -q`
Expected: PASS (all tests, no failures).

- [ ] **Step 2: Lint**

Run: `uv run ruff check src/ tests/`
Expected: no errors. If ruff flags the unused `aborted`/`caught` or an import, fix per its message and re-run.

- [ ] **Step 3: Commit any lint fixes (only if changes were needed)**

```bash
git add -A
git commit -m "chore: lint fixes for reachability daemon shutdown (#12)"
```
