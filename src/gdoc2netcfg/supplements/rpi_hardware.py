"""Supplement: Raspberry Pi hardware identity, probed over SSH.

For every Raspberry Pi in the sheet (a host with an interface on a
Raspberry Pi OUI, or a name beginning ``rpi``/``reterm``), run
``data/detect_pi_hardware.py`` on the host and keep its fixed-shape
summary: the boards on the 40-pin header (HAT ID EEPROMs at ``0x50`` and,
read straight off the ID bus, at ``0x51``–``0x57`` — Waveshare's PoE M.2
HAT+ (B) sits at ``0x52``, where the firmware never looks), what powers it
(a GPIO PoE HAT, the Zero PoE bonnet, a USB-C supply, or honestly
``ambiguous``/``undetermined``), the FPGA boards it hosts (NeTV2 by PCIe id
and BAR layout, Acorn by the same, Arty by its Digilent FT2232 serial), and
on a Pi 5 whether an RTC cell and a fan are fitted.

The probe is a stand-alone python3 (>= 3.5) script fed to the host over
stdin — nothing is installed on the host — and it needs ``sudo`` without a
password for ``i2ctransfer``/``i2cdetect``/``vcgencmd``. Its canonical copy
is rpi-hdcp-output ``tools/detect_pi_hardware.py``; the copy here is the one
that runs.

This is a Supplement, not a Source: it enriches sheet hosts with facts
read from the machines themselves and persists them in the DiscoveryDB
(``rpi_hardware``), from which ``rpi_hardware_sheet`` writes the
"RPi Hardware" tab.
"""

from __future__ import annotations

import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from importlib import resources
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gdoc2netcfg.models.host import Host
    from gdoc2netcfg.supplements.reachability import HostReachability

# Raspberry Pi OUIs: the Foundation (1/2/3/Zero), Trading Ltd (4, early 5)
# and Ltd (5). Same list as the fleet audit's is_rpi_mac.
RPI_OUIS = frozenset({
    "b8:27:eb", "dc:a6:32", "e4:5f:01", "2c:cf:67", "88:a2:9e", "98:fe:54",
})

PROBE_RESOURCE = "detect_pi_hardware.py"
DEFAULT_USERS = ("tim", "pi")


@dataclass
class RpiHardware:
    """One host's probe summary, as stored (see storage: rpi_hardware)."""

    model: str
    serial: str
    revision: str
    power_class: str
    header: list[str] = field(default_factory=list)
    fpga: list[dict[str, str]] = field(default_factory=list)
    rtc_battery: bool | None = None
    fan: bool | None = None
    max_current_ma: int | None = None
    probe_user: str = ""

    def to_doc(self) -> dict:
        return {
            "model": self.model, "serial": self.serial, "revision": self.revision,
            "power_class": self.power_class, "rtc_battery": self.rtc_battery,
            "fan": self.fan, "max_current_ma": self.max_current_ma,
            "probe_user": self.probe_user,
            "header": list(self.header), "fpga": [dict(b) for b in self.fpga],
        }

    @classmethod
    def from_doc(cls, doc: dict) -> RpiHardware:
        return cls(**doc)


def is_rpi_host(host: Host) -> bool:
    """A Pi by OUI or by name; the fpgas.online pool's ``piN.fpgas`` rows
    and non-Pi ``hifive`` boards are not."""
    name = host.machine_name.lower()
    if re.match(r"pi\d+\.fpgas", name) or name.startswith("hifive"):
        return False
    if name.startswith("rpi") or name.startswith("reterm"):
        return True
    return any(
        str(iface.mac).lower()[:8] in RPI_OUIS
        for iface in host.interfaces if iface.mac
    )


def probe_script() -> str:
    """The probe's source, from package data."""
    return resources.files("gdoc2netcfg.supplements.data").joinpath(
        PROBE_RESOURCE
    ).read_text()


def parse_probe_output(stdout: str, user: str) -> RpiHardware:
    """The probe's ``--json`` output to a record.

    Some images print a login banner before the JSON; parse from the
    first brace. Anything that does not decode, or lacks the summary,
    is an error: the probe changed shape, or did not run.
    """
    start = stdout.find("{")
    if start < 0:
        raise ValueError(f"no JSON in probe output: {stdout[-200:]!r}")
    doc = json.loads(stdout[start:])
    try:
        summary = doc["verdict"]["summary"]
    except (KeyError, TypeError) as exc:
        raise ValueError("probe output has no verdict.summary") from exc
    for key in ("model", "serial", "revision", "power_class", "header", "fpga"):
        if key not in summary:
            raise ValueError(f"probe summary lacks {key!r}")
    return RpiHardware(
        model=summary["model"], serial=summary["serial"] or "",
        revision=summary["revision"] or "", power_class=summary["power_class"],
        header=list(summary["header"]),
        fpga=[{k: v for k, v in board.items() if k in ("kind", "serial", "dna", "idcode")}
              for board in summary["fpga"]],
        rtc_battery=summary.get("rtc_battery"), fan=summary.get("fan"),
        max_current_ma=summary.get("max_current_ma"), probe_user=user,
    )


def _ssh_probe(
    ip: str, users: tuple[str, ...], script: str, jtag: bool, timeout: int,
) -> tuple[str, str] | None:
    """Run the probe as the first user that logs in; (user, stdout) or None."""
    args = "--json --jtag" if jtag else "--json"
    for user in users:
        try:
            result = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
                 "-o", "StrictHostKeyChecking=accept-new",
                 f"{user}@{ip}", f"python3 - {args}"],
                input=script, capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        if result.returncode == 0:
            return user, result.stdout
        err = result.stderr
        if any(s in err for s in ("Permission denied", "Connection closed")):
            continue        # try the next user
        return None         # unreachable: no point in other users
    return None


def scan_rpi_hardware(
    hosts: list[Host],
    *,
    reachability: dict[str, HostReachability],
    users: tuple[str, ...] = DEFAULT_USERS,
    jtag_hosts: frozenset[str] = frozenset(),
    timeout: int = 120,
    max_workers: int = 6,
    verbose: bool = False,
) -> tuple[dict[str, dict], list[str]]:
    """Probe every reachable Pi. Returns (hostname -> doc, errors).

    A Pi that is in the sheet but not reachable, or that no configured
    user can log in to, is an error line, not a silent gap: the caller
    persists what did scan and then raises for the rest.
    """
    script = probe_script()
    targets: list[tuple[Host, str]] = []
    errors: list[str] = []
    for host in hosts:
        if not is_rpi_host(host):
            continue
        reach = reachability.get(host.hostname)
        if reach is None or not reach.is_up:
            errors.append(f"{host.hostname}: not reachable, not probed")
            continue
        targets.append((host, reach.active_ips[0]))

    results: dict[str, dict] = {}

    def _one(item: tuple[Host, str]) -> tuple[str, RpiHardware | None, str]:
        host, ip = item
        got = _ssh_probe(ip, users, script, host.hostname in jtag_hosts, timeout)
        if got is None:
            return host.hostname, None, f"{host.hostname}: no configured user could log in at {ip}"
        user, stdout = got
        try:
            return host.hostname, parse_probe_output(stdout, user), ""
        except ValueError as exc:
            return host.hostname, None, f"{host.hostname}: {exc}"

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_one, t) for t in targets]
        for fut in as_completed(futures):
            hostname, record, err = fut.result()
            if record is None:
                errors.append(err)
                if verbose:
                    print(f"  {hostname}: FAILED ({err})")
                continue
            results[hostname] = record.to_doc()
            if verbose:
                boards = ", ".join(
                    b.get("dna") or b.get("serial") or b["kind"] for b in record.fpga
                ) or "no fpga"
                print(f"  {hostname}: {record.model}; header {record.header or 'bare'}; "
                      f"power {record.power_class}; {boards}")
    return dict(sorted(results.items())), sorted(errors)


def raise_for_rpi_hardware_errors(errors: list[str]) -> None:
    if errors:
        raise RuntimeError(
            "rpi-hardware scan did not cover every Pi:\n  " + "\n  ".join(errors)
        )
