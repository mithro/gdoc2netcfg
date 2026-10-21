"""THROWAWAY probe: how rsyslog 8.2608 lookup_table behaves for the sender-name table.

Runs an UNPRIVILEGED rsyslogd (never the system daemon) on 127.0.0.1:15514 with
a ruleset shaped like the planned generator output, then sends datagrams from
127.0.0.1 (in the table) and 127.0.0.2 (not in it) and lists the files written.

Answers, before writing the generator:
  - does lookup() return the table's "nomatch" value on a miss, and does an
    empty nomatch let the ruleset substitute unknown-<ip>?
  - is $fromhost-ip the bare dotted-quad (what the table must be keyed on)?
  - does the hostname a device claims in its header stop mattering?

Usage (from the worktree root):  uv run python tmp/lookup_probe.py
"""

import json
import pathlib
import signal
import socket
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parent / "lookup_probe"
ROOT.mkdir(exist_ok=True)
LOGS = ROOT / "logs"
TABLE = ROOT / "names.json"
CONF = ROOT / "rsyslog.conf"
PID = ROOT / "rsyslogd.pid"

TABLE.write_text(json.dumps({
    "version": 1, "nomatch": "", "type": "string",
    "table": [{"index": "127.0.0.1", "value": "bmc.big-storage"}],
}))
CONF.write_text(f"""\
global(workDirectory="{ROOT}")
module(load="imudp")
lookup_table(name="remote-names" file="{TABLE}" reloadOnHUP="on")
template(name="RemoteLog-net" type="string"
         string="{LOGS}/net/%$.name:::secpath-replace%.log")
ruleset(name="remote-net") {{
    set $.name = lookup("remote-names", $fromhost-ip);
    if $.name == "" then {{
        set $.name = "unknown-" & $fromhost-ip;
    }}
    action(type="omfile" dynaFile="RemoteLog-net" dirCreateMode="0755")
}}
input(type="imudp" port="15514" address="127.0.0.1" ruleset="remote-net")
""")

check = subprocess.run(["rsyslogd", "-N1", "-f", str(CONF)],
                       capture_output=True, text=True)
print("rsyslogd -N1 rc", check.returncode, check.stdout.strip(), check.stderr.strip())

daemon = subprocess.Popen(["rsyslogd", "-n", "-f", str(CONF), "-i", str(PID)])
time.sleep(1.5)
try:
    for src, claimed in (("127.0.0.1", "ATEN"), ("127.0.0.2", "../../etc/x")):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((src, 0))
        s.sendto(f"<11>Oct 21 20:00:00 {claimed} test: from {src}".encode(),
                 ("127.0.0.1", 15514))
        s.close()
    time.sleep(1.5)
finally:
    daemon.send_signal(signal.SIGTERM)
    daemon.wait(timeout=10)

for f in sorted(LOGS.rglob("*")):
    if f.is_file():
        print(f.relative_to(ROOT), "->", f.read_text().strip())
