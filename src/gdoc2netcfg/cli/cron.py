"""Cron job management for gdoc2netcfg.

Provides commands to install, show, and uninstall scheduled cron jobs
that keep cached data and generated config files up to date, plus the
``cron run`` wrapper every installed line goes through.

Why a wrapper: cron mails the crontab owner whatever a job prints and
ignores exit codes entirely, so the old ``... >>cron.log 2>&1`` lines
turned every traceback into silence (the nightly ``sshfp`` scan failed
for two weeks unnoticed).  ``cron run <name>`` takes the per-job flock,
streams the job's combined output into ``.cache/cron.log`` between
timestamped START/END markers, and prints a summary plus the last lines
of output on stdout ONLY when the job fails or is skipped because the
lock is held — so root gets mail exactly when something is wrong.
"""

from __future__ import annotations

import argparse
import fcntl
import shutil
import socket
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class CronEntry:
    """A single cron job entry."""

    schedule: str       # e.g. "*/15 * * * *"
    command: str        # e.g. "gdoc2netcfg fetch"
    lock_name: str      # e.g. "fetch" (used for flock lock file name)
    comment: str        # e.g. "Fetch CSVs from Google Sheets"


def detect_uv_path() -> Path:
    """Find the uv binary.

    Checks shutil.which() first, then ~/.local/bin/uv, then /usr/local/bin/uv.
    Raises FileNotFoundError with install instructions if not found.
    """
    # Try PATH first
    which_result = shutil.which("uv")
    if which_result is not None:
        return Path(which_result)

    # Try ~/.local/bin/uv
    local_uv = Path.home() / ".local" / "bin" / "uv"
    if local_uv.exists():
        return local_uv

    # Try /usr/local/bin/uv
    system_uv = Path("/usr/local/bin/uv")
    if system_uv.exists():
        return system_uv

    raise FileNotFoundError(
        "uv not found. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    )


def detect_project_root(start: Path | None = None) -> Path:
    """Find the project root by walking up from start looking for gdoc2netcfg.toml.

    Raises FileNotFoundError if not found.
    """
    current = (start or Path.cwd()).resolve()
    while True:
        if (current / "gdoc2netcfg.toml").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent

    raise FileNotFoundError(
        "gdoc2netcfg.toml not found in current directory or any parent. "
        "Run this command from the gdoc2netcfg project directory."
    )


def generate_cron_entries(*, zigbee: bool = False) -> list[CronEntry]:
    """Generate the list of cron entries for the agreed schedule.

    Each command persists its results to the SQLite databases (delta-based),
    so scheduling them builds up historical data over time.  Reachability is
    intentionally NOT here — it is handled by the ``gdoc2netcfg-reachability``
    systemd daemon (every 5 minutes), which also publishes to MQTT.

    *zigbee* adds the hourly zigbee scan — config-gated on the
    ``[zigbee]`` section; the broker comes from ``[homeassistant.mqtt]``
    and the scan runs against this site's local Z2M instance.

    Under the production "everything root" model the databases are root-owned,
    so install this as root (``sudo gdoc2netcfg cron install``) — the scans
    need write access to the DBs.
    """
    entries = [
        # Every 15 minutes: fetch + generate
        CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg fetch",
            lock_name="fetch",
            comment="Fetch CSVs from Google Sheets",
        ),
        CronEntry(
            schedule="*/15 * * * *",
            command="gdoc2netcfg generate",
            lock_name="generate",
            comment="Generate config files from cached data",
        ),
        # Daily 02:00: sshfp
        CronEntry(
            schedule="0 2 * * *",
            command="gdoc2netcfg sshfp",
            lock_name="sshfp",
            comment="Scan SSH fingerprints",
        ),
        # Daily 02:05: ssl-certs
        CronEntry(
            schedule="5 2 * * *",
            command="gdoc2netcfg ssl-certs",
            lock_name="ssl-certs",
            comment="Scan SSL/TLS certificates",
        ),
        # Daily 02:10: tasmota
        CronEntry(
            schedule="10 2 * * *",
            command="gdoc2netcfg tasmota scan",
            lock_name="tasmota",
            comment="Scan IoT VLAN for Tasmota devices",
        ),
        # Hourly at :15: zigbee — appended below when configured
        # Daily 03:00: snmp-host
        CronEntry(
            schedule="0 3 * * *",
            command="gdoc2netcfg snmp-host",
            lock_name="snmp-host",
            comment="Scan hosts for SNMP system info",
        ),
        # Daily 03:05: bridge (unified switch data: SNMP-switch + NSDP)
        CronEntry(
            schedule="5 3 * * *",
            command="gdoc2netcfg bridge scan",
            lock_name="bridge",
            comment="Scan switches for bridge/topology data (SNMP + NSDP)",
        ),
        # Weekly Sunday 04:00: bmc-firmware
        CronEntry(
            schedule="0 4 * * 0",
            command="gdoc2netcfg bmc-firmware",
            lock_name="bmc-firmware",
            comment="Scan BMC firmware information",
        ),
    ]
    if zigbee:
        entries.append(CronEntry(
            schedule="15 * * * *",
            command="gdoc2netcfg zigbee scan",
            lock_name="zigbee",
            comment="Scan Zigbee2MQTT sites for device data",
        ))
    return entries


def zigbee_configured(project_root: Path) -> bool:
    """True if the project's gdoc2netcfg.toml has a [zigbee] section."""
    from gdoc2netcfg.config import load_config

    config = load_config(project_root / "gdoc2netcfg.toml")
    return config.zigbee.enabled


_BEGIN_MARKER = "# BEGIN gdoc2netcfg managed entries - DO NOT EDIT THIS BLOCK"
_END_MARKER = "# END gdoc2netcfg managed entries"


def _validate_no_whitespace(path: Path, label: str) -> None:
    """Raise ValueError if path contains whitespace (unsafe for unquoted cron lines)."""
    path_str = str(path)
    if any(c.isspace() for c in path_str):
        raise ValueError(
            f"{label} path contains whitespace, which is unsafe in crontab lines: {path_str}"
        )


def cron_paths(project_root: Path, lock_name: str) -> tuple[Path, Path]:
    """(lock_file, log_file) for a job — shared by the crontab line and the
    ``cron run`` wrapper so the two can never disagree."""
    cache = project_root / ".cache"
    return cache / f"cron-{lock_name}.lock", cache / "cron.log"


def format_cron_line(entry: CronEntry, uv_path: Path, project_root: Path) -> str:
    """Format a single CronEntry as a crontab line.

    The line runs ``gdoc2netcfg cron run <lock_name>`` (see run_cron_job),
    which does the locking and logging itself.  There is deliberately NO
    shell redirect: whatever the wrapper prints must reach cron so that it
    is mailed.  ``uv --quiet`` keeps uv's own chatter (env sync messages)
    off that channel; real uv failures still surface.

    Raises ValueError if either path contains whitespace (would break
    unquoted shell expansion in crontab).
    """
    _validate_no_whitespace(uv_path, "uv")
    _validate_no_whitespace(project_root, "Project root")
    return (
        f"{entry.schedule} "
        f"{uv_path} --quiet --directory {project_root} "
        f"run gdoc2netcfg cron run {entry.lock_name}"
    )


# ---------------------------------------------------------------------------
# cron run — the per-job wrapper
# ---------------------------------------------------------------------------

#: Exit status when a run is skipped because the previous one still holds
#: the lock (sysexits.h EX_TEMPFAIL).
EXIT_LOCK_HELD = 75

#: How many trailing output lines a failure report carries.  Tracebacks
#: are at the end; the full output is always in cron.log.
DEFAULT_TAIL_LINES = 200


def resolve_job_argv(lock_name: str, entries: list[CronEntry]) -> list[str]:
    """argv that runs the job named *lock_name* in THIS interpreter.

    ``entry.command`` is ``"gdoc2netcfg <sub> [args]"``; the words after
    ``gdoc2netcfg`` are handed to ``python -m gdoc2netcfg.cli.main`` so the
    wrapper and the job share one venv regardless of how uv was invoked.

    Raises KeyError for an unknown name.
    """
    for entry in entries:
        if entry.lock_name == lock_name:
            words = entry.command.split()
            if words[:1] != ["gdoc2netcfg"]:
                raise ValueError(
                    f"Cron entry {lock_name!r} command does not start with "
                    f"'gdoc2netcfg': {entry.command!r}"
                )
            return [sys.executable, "-m", "gdoc2netcfg.cli.main", *words[1:]]
    known = ", ".join(sorted(e.lock_name for e in entries))
    raise KeyError(f"No cron job named {lock_name!r} (known: {known})")


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def run_cron_job(
    lock_name: str,
    argv: list[str],
    *,
    lock_file: Path,
    log_file: Path,
    tail_lines: int = DEFAULT_TAIL_LINES,
) -> int:
    """Run one cron job under its flock, logging everything, loud on failure.

    - Takes ``flock(2)`` LOCK_EX|LOCK_NB on *lock_file* (the same lock the
      old ``flock -n`` crontab lines used, so old- and new-style runs of the
      same job still exclude each other).  If it is held, the job is
      SKIPPED: a one-line report goes to stdout (so cron mails it — a job
      that never gets to run is a failure, not a non-event) and the return
      value is EXIT_LOCK_HELD.
    - Streams the job's stdout+stderr line by line into *log_file* between
      ``==== <ts> START`` / ``==== <ts> END ... exit=N`` markers, flushing
      per line so ``tail -f cron.log`` shows progress.
    - Prints NOTHING on success.  On non-zero exit prints a summary and the
      last *tail_lines* lines of output to stdout, then returns the job's
      exit status.
    """
    label = f"gdoc2netcfg {lock_name}"
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    with open(lock_file, "w") as lock_fh, open(log_file, "a") as log:
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log.write(
                f"==== {_timestamp()} SKIPPED {label}: lock {lock_file} "
                f"is held by another run\n"
            )
            print(
                f"{label} SKIPPED on {socket.gethostname()}: lock {lock_file} "
                f"is still held by a previous run (hung or overrunning?)"
            )
            print(f"Full log: {log_file}")
            return EXIT_LOCK_HELD

        started = time.monotonic()
        log.write(f"==== {_timestamp()} START {label}: {' '.join(argv)}\n")
        log.flush()

        tail: deque[str] = deque(maxlen=tail_lines)
        total = 0
        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except OSError as exc:
            line = f"failed to start {argv[0]}: {exc}\n"
            log.write(line)
            tail.append(line)
            total = 1
            rc = 127
        else:
            assert proc.stdout is not None
            for line in proc.stdout:
                log.write(line)
                log.flush()
                tail.append(line)
                total += 1
            rc = proc.wait()

        elapsed = round(time.monotonic() - started)
        log.write(f"==== {_timestamp()} END {label} exit={rc} ({elapsed}s)\n")

    if rc == 0:
        return 0

    print(
        f"{label} FAILED on {socket.gethostname()}: exit status {rc} "
        f"after {elapsed}s"
    )
    print(f"Command: {' '.join(argv)}")
    print(f"Full log: {log_file}")
    if total > len(tail):
        print(f"Last {len(tail)} of {total} output lines:")
    else:
        print(f"Output ({total} lines):")
    body = "".join(tail)
    if body and not body.endswith("\n"):
        body += "\n"
    print(body, end="")
    return rc


def format_crontab_block(
    entries: list[CronEntry],
    uv_path: Path,
    project_root: Path,
) -> str:
    """Format all entries as a managed crontab block with BEGIN/END markers."""
    lines = [
        _BEGIN_MARKER,
        f"# Project: {project_root}",
        "",
    ]

    for entry in entries:
        lines.append(f"# {entry.comment}")
        lines.append(format_cron_line(entry, uv_path, project_root))

    lines.append("")
    lines.append(_END_MARKER)
    lines.append("")  # trailing newline

    return "\n".join(lines)


def read_current_crontab() -> str:
    """Read the current user's crontab.

    Returns empty string if the user has no crontab.
    Re-raises CalledProcessError for unexpected failures (e.g. permission denied).
    """
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        # "no crontab for <user>" is the expected error when user has no crontab
        if "no crontab for" in (e.stderr or ""):
            return ""
        raise


def write_crontab(content: str) -> None:
    """Write content as the user's crontab by piping to 'crontab -'."""
    subprocess.run(
        ["crontab", "-"],
        input=content,
        text=True,
        check=True,
    )


def remove_managed_block(crontab: str) -> str:
    """Remove the gdoc2netcfg managed block from a crontab string.

    Returns the crontab with the block (between BEGIN/END markers) removed.
    Preserves all other content.

    Raises ValueError if markers are mismatched (BEGIN without END, or
    END without BEGIN), to prevent silent data loss from a corrupted crontab.
    """
    lines = crontab.splitlines(keepends=True)
    result: list[str] = []
    inside_block = False

    for line in lines:
        stripped = line.rstrip("\n")
        if stripped == _BEGIN_MARKER:
            inside_block = True
            continue
        if stripped == _END_MARKER:
            if not inside_block:
                raise ValueError(
                    "Corrupted crontab: found END marker without preceding BEGIN marker. "
                    "Please fix your crontab manually (crontab -e)."
                )
            inside_block = False
            continue
        if not inside_block:
            result.append(line)

    if inside_block:
        raise ValueError(
            "Corrupted crontab: found BEGIN marker without matching END marker. "
            "Please fix your crontab manually (crontab -e)."
        )

    # Clean up trailing blank lines
    text = "".join(result)
    if text:
        text = text.rstrip("\n") + "\n"
    return text


def add_managed_block(crontab: str, block: str) -> str:
    """Add a managed block to a crontab, replacing any existing one.

    Removes the old block first (if present), then appends the new one.
    """
    cleaned = remove_managed_block(crontab)
    if cleaned and not cleaned.endswith("\n"):
        cleaned += "\n"
    return cleaned + block


# ---------------------------------------------------------------------------
# CLI command handlers
# ---------------------------------------------------------------------------


def cmd_cron_show() -> int:
    """Print the crontab block that would be installed."""
    uv_path = detect_uv_path()
    project_root = detect_project_root()
    entries = generate_cron_entries(zigbee=zigbee_configured(project_root))
    block = format_crontab_block(entries, uv_path, project_root)

    print(f"# uv path: {uv_path}")
    print(f"# Project root: {project_root}")
    print()
    print(block)
    return 0


def cmd_cron_install() -> int:
    """Install cron entries into the user's crontab."""
    uv_path = detect_uv_path()
    project_root = detect_project_root()
    entries = generate_cron_entries(zigbee=zigbee_configured(project_root))
    block = format_crontab_block(entries, uv_path, project_root)

    current = read_current_crontab()
    new_crontab = add_managed_block(current, block)
    write_crontab(new_crontab)

    print(f"Installed {len(entries)} cron entries.", file=sys.stderr)
    print(f"  uv: {uv_path}", file=sys.stderr)
    print(f"  project: {project_root}", file=sys.stderr)
    return 0


def cmd_cron_uninstall() -> int:
    """Remove gdoc2netcfg cron entries from the user's crontab."""
    current = read_current_crontab()

    if _BEGIN_MARKER not in current:
        print("No gdoc2netcfg cron entries found in crontab.", file=sys.stderr)
        return 0

    cleaned = remove_managed_block(current)
    write_crontab(cleaned)

    print("Removed gdoc2netcfg cron entries.", file=sys.stderr)
    return 0


def cmd_cron_run(args: argparse.Namespace) -> int:
    """Run one scheduled job under the wrapper (what the crontab lines call)."""
    project_root = detect_project_root()
    entries = generate_cron_entries(zigbee=zigbee_configured(project_root))
    try:
        argv = resolve_job_argv(args.name, entries)
    except KeyError as exc:
        print(f"gdoc2netcfg cron run: {exc.args[0]}", file=sys.stderr)
        return 2
    lock_file, log_file = cron_paths(project_root, args.name)
    return run_cron_job(
        args.name, argv,
        lock_file=lock_file, log_file=log_file, tail_lines=args.tail_lines,
    )


def cmd_cron(args: argparse.Namespace) -> int:
    """Dispatch to the appropriate cron subcommand."""
    handlers = {
        "show": lambda: cmd_cron_show(),
        "install": lambda: cmd_cron_install(),
        "uninstall": lambda: cmd_cron_uninstall(),
        "run": lambda: cmd_cron_run(args),
    }

    subcommand = getattr(args, "cron_command", None)
    if subcommand is None:
        print("Usage: gdoc2netcfg cron {show|install|uninstall|run}")
        return 0

    return handlers[subcommand]()
