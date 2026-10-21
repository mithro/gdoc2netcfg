"""THROWAWAY end-to-end check: the GENERATED alert config, on a throwaway rsyslogd.

Builds the welland inventory from /opt/gdoc2netcfg's cache (read-only), runs
generate_rsyslog with alert settings, then rewrites ONLY what must differ to run
unprivileged beside the live daemon:
  ownership (unprivileged daemon cannot chown), ports 514 -> 15514 and 6666 -> 16666 (same leg addresses; the live daemon
  holds 514/6666 there), /var/log -> tmp dir, the table path -> the generated
  table, SMTP 127.0.0.1:25 -> an in-process sink on 127.0.0.1:15025 (so no mail
  leaves the host).
Then sends, to the net leg 10.1.5.1:15514:
  1. the real 2026-10-20 IERR line from source 10.1.5.1 (a known sender)
  2. an Information line from 10.1.5.1           (must NOT mail)
  3. a line from source 127.0.0.1 (not in the table -> unknown-127.0.0.1)
and prints the files written and every mail received.

Usage (worktree root):  env --chdir=/opt/gdoc2netcfg <wt>/.venv/bin/python <wt>/tmp/alerts_e2e.py
"""

import argparse
import pathlib
import signal
import socket
import subprocess
import sys
import threading
import time

WT = pathlib.Path(__file__).resolve().parents[1]
mails: list[str] = []


def smtp_sink(stop: threading.Event, server: socket.socket) -> None:
    server.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = server.accept()
        except TimeoutError:
            continue
        with conn:
            f = conn.makefile("rwb")
            f.write(b"220 sink\r\n"); f.flush()
            data, in_data = [], False
            for raw in f:
                line = raw.decode(errors="replace")
                if in_data:
                    if line.rstrip("\r\n") == ".":
                        mails.append("".join(data)); in_data = False
                        f.write(b"250 ok\r\n"); f.flush()
                    else:
                        data.append(line)
                    continue
                verb = line[:4].upper()
                if verb == "DATA":
                    data, in_data = [], True
                    f.write(b"354 go\r\n")
                elif verb == "QUIT":
                    f.write(b"221 bye\r\n"); f.flush(); break
                else:
                    f.write(b"250 ok\r\n")
                f.flush()



from gdoc2netcfg.cli.main import _build_pipeline, _load_config  # noqa: E402
from gdoc2netcfg.generators.rsyslog import generate_rsyslog  # noqa: E402

ROOT = WT / "tmp" / "alerts_e2e"
ROOT.mkdir(exist_ok=True)

config = _load_config(argparse.Namespace(config="gdoc2netcfg.toml"))
_, _, inventory, _ = _build_pipeline(config)
out = generate_rsyslog(
    inventory,
    alert_mail_to="alerts@probe", alert_mail_from="rsyslog@probe",
    alert_smtp_server="127.0.0.1", alert_smtp_port=25, alert_interval=5,
    alert_unknown_interval=5,
)
table = ROOT / "names.json"
table.write_text(out["rsyslog.d/remote-logs.names.json"])
conf = out["rsyslog.d/remote-logs.conf"]
conf = (conf.replace('port="514"', 'port="15514"')
            .replace('port="6666"', 'port="16666"')
            .replace("/var/log/", f"{ROOT}/logs/")
            .replace("/etc/rsyslog.d/remote-logs.names.json", str(table))
            .replace('server="127.0.0.1" port="25"', 'server="127.0.0.1" port="15025"')
            # unprivileged: rsyslogd cannot chown to root:adm
            .replace('fileOwner="root" fileGroup="adm"\n', ""))
(ROOT / "rsyslog.conf").write_text(f'global(workDirectory="{ROOT}")\n' + conf)

check = subprocess.run(["rsyslogd", "-N1", "-f", str(ROOT / "rsyslog.conf")],
                       capture_output=True, text=True)
print("rsyslogd -N1 rc", check.returncode,
      [line for line in check.stderr.splitlines() if "error" in line.lower()])

IERR = ("<9>Oct 20 07:30:04 10.1.5.150 ipmi: Health EventLog | 2026/10/20 07:30:04 "
        "| 10.1.5.150 | Critical | IERR - Assertion | Processor(OEM)")
INFO = ("<14>Oct 21 14:07:49 10.1.5.150 ipmi: Maintenance EventLog | 2026/10/21 14:07:49 "
        "| 10.1.5.150 | Information | Web logout was successful. | WEB ADMIN(ADMIN)")


def send(src: str, msg: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.sendto(msg.encode(), ("10.1.5.1", 15514))
    s.close()


server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 15025))
server.listen()
stop = threading.Event()
sink = threading.Thread(target=smtp_sink, args=(stop, server))
sink.start()
daemon = subprocess.Popen(["rsyslogd", "-n", "-f", str(ROOT / "rsyslog.conf"),
                           "-i", str(ROOT / "rsyslogd.pid")])
time.sleep(2)
try:
    send("10.1.5.1", IERR)
    send("10.1.5.1", INFO)
    send("127.0.0.1", "<14>Oct 22 01:00:00 stranger test: hello")
    time.sleep(4)
finally:
    daemon.send_signal(signal.SIGTERM)
    daemon.wait(timeout=20)
    stop.set()
    sink.join()
    server.close()

for f in sorted((ROOT / "logs").rglob("*")):
    if f.is_file():
        print("file", f.relative_to(ROOT), f"({len(f.read_text().splitlines())} lines)")
print(f"{len(mails)} mail(s)")
for m in mails:
    print("-----")
    print("\n".join(line for line in m.splitlines() if line.startswith(("Subject", "To", "From"))))
