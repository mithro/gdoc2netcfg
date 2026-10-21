"""THROWAWAY: re-run the review's two failing alert scenarios on the GENERATED config.

Same harness as tmp/alerts_e2e.py (welland inventory from /opt, read-only;
unprivileged daemon on high ports; SMTP sink on 127.0.0.1:15025, so no mail
leaves the host), with both intervals at 10 s so the window is wide open.
  (a) Warning from 10.1.5.1, then 0.5 s later a Critical from 10.1.5.1, then a
      Critical from 127.0.0.1: before the fix one shared action mailed only the
      Warning. Expect 3 BMC mails, plus 1 unknown-sender mail for 127.0.0.1.
  (c) a forged Critical from 127.0.0.2, a non-BMC sender: must NOT mail as a
      BMC event (the BMC rules match only sheet-marked BMC addresses). The
      harness adds the two test senders 10.1.5.1 and 127.0.0.1 to the BMC
      address list, since no local address can be a real BMC's.
  (b) SMTP down: a Critical arrives, rsyslogd is stopped and restarted, then
      SMTP comes up. Before the fix the in-memory queue lost it. Expect the
      Critical to be delivered after the restart.
Usage: env --chdir=/opt/gdoc2netcfg <wt>/.venv/bin/python <wt>/tmp/alerts_review_probe.py
"""

import argparse
import pathlib
import signal
import socket
import subprocess
import threading
import time

from gdoc2netcfg.cli.main import _build_pipeline, _load_config
from gdoc2netcfg.generators.rsyslog import generate_rsyslog

WT = pathlib.Path(__file__).resolve().parents[1]
ROOT = WT / "tmp" / "alerts_review_probe"
ROOT.mkdir(exist_ok=True)
mails: list[str] = []


def smtp_sink(stop, server):
    server.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = server.accept()
        except TimeoutError:
            continue
        with conn:
            f = conn.makefile("rwb")
            f.write(b"220 sink\r\n")
            f.flush()
            data, in_data = [], False
            for raw in f:
                line = raw.decode(errors="replace")
                if in_data:
                    if line.rstrip("\r\n") == ".":
                        mails.append("".join(data))
                        in_data = False
                        f.write(b"250 ok\r\n")
                        f.flush()
                    else:
                        data.append(line)
                    continue
                verb = line[:4].upper()
                if verb == "DATA":
                    data, in_data = [], True
                    f.write(b"354 go\r\n")
                elif verb == "QUIT":
                    f.write(b"221 bye\r\n")
                    f.flush()
                    break
                else:
                    f.write(b"250 ok\r\n")
                f.flush()


class Sink:
    def __enter__(self):
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 15025))
        self.server.listen()
        self.stop = threading.Event()
        self.t = threading.Thread(target=smtp_sink, args=(self.stop, self.server))
        self.t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.t.join()
        self.server.close()


config = _load_config(argparse.Namespace(config="gdoc2netcfg.toml"))
_, _, inventory, _ = _build_pipeline(config)
out = generate_rsyslog(
    inventory, alert_mail_to="alerts@probe", alert_mail_from="rsyslog@probe",
    alert_smtp_server="127.0.0.1", alert_smtp_port=25,
    alert_interval=10, alert_unknown_interval=10,
)
table = ROOT / "names.json"
table.write_text(out["rsyslog.d/remote-logs.names.json"])
conf = (out["rsyslog.d/remote-logs.conf"]
        .replace('port="514"', 'port="15514"')
        .replace('port="6666"', 'port="16666"')
        .replace("/var/log/", f"{ROOT}/logs/")
        .replace("/etc/rsyslog.d/remote-logs.names.json", str(table))
        .replace('server="127.0.0.1" port="25"', 'server="127.0.0.1" port="15025"')
        .replace('fileOwner="root" fileGroup="adm"\n', "")
        .replace('action.resumeInterval="30"', 'action.resumeInterval="2"')
        .replace('$fromhost-ip == "10.1.5.150"',
                 '$fromhost-ip == "10.1.5.150" or $fromhost-ip == "10.1.5.1" '
                 'or $fromhost-ip == "127.0.0.1"'))
assert conf.count('$fromhost-ip == "127.0.0.1"') > 0, "BMC condition not found"
(ROOT / "rsyslog.conf").write_text(f'global(workDirectory="{ROOT}")\n' + conf)
check = subprocess.run(["rsyslogd", "-N1", "-f", str(ROOT / "rsyslog.conf")],
                       capture_output=True, text=True)
print("rsyslogd -N1 rc", check.returncode)


def bmc_line(sev, event):
    return (f"<9>Oct 22 01:00:00 bmc ipmi: Health EventLog | 2026/10/22 01:00:00 "
            f"| 10.1.5.150 | {sev} | {event} | Processor(OEM)")


def send(src, msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    s.sendto(msg.encode(), ("10.1.5.1", 15514))
    s.close()


def start_daemon():
    return subprocess.Popen(["rsyslogd", "-n", "-f", str(ROOT / "rsyslog.conf"),
                             "-i", str(ROOT / "rsyslogd.pid")])


def stop_daemon(d):
    d.send_signal(signal.SIGTERM)
    d.wait(timeout=30)


def subjects():
    return [ln for m in mails for ln in m.splitlines() if ln.startswith("Subject")]


with Sink():
    d = start_daemon()
    time.sleep(2)
    send("10.1.5.1", bmc_line("Warning", "Fan low - Assertion"))
    time.sleep(0.5)
    send("10.1.5.1", bmc_line("Critical", "IERR - Assertion"))
    time.sleep(0.5)
    send("127.0.0.1", bmc_line("Critical", "PSU failure - Assertion"))
    time.sleep(0.5)
    send("127.0.0.2", bmc_line("Critical", "Forged - Assertion"))
    time.sleep(4)
    stop_daemon(d)
print("(a)+(c)", subjects())

mails.clear()
d = start_daemon()            # SMTP down
time.sleep(2)
send("10.1.5.1", bmc_line("Critical", "Second IERR - Assertion"))
time.sleep(3)
stop_daemon(d)
print("(b) spool after stop:", sorted(p.name for p in ROOT.iterdir() if p.name.startswith("alert-")))
with Sink():
    d = start_daemon()
    time.sleep(8)
    stop_daemon(d)
print("(b)", subjects())
