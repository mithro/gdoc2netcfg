"""THROWAWAY probe: rsyslog 8.2608 ommail behaviour for the BMC / unknown-sender alerts.

Runs an UNPRIVILEGED rsyslogd (never the system daemon) on 127.0.0.1:15514 and a
minimal in-process SMTP sink on 127.0.0.1:15025 (never the real postfix on :25,
so no mail leaves this host). Sends the real 2026-10-20 big-storage IERR line,
a duplicate of it, and an Information line, then reports:
  - which datagrams produced a mail, with the subject and body as delivered;
  - whether action.execOnlyOnceEveryInterval suppressed the duplicate;
  - phase 2: with the sink STOPPED, whether the log file still gets the line
    (the mail action has its own queue, so SMTP being down must not block it).

Usage (from the worktree root):  uv run python tmp/ommail_probe.py
"""

import pathlib
import signal
import socket
import subprocess
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent / "ommail_probe"
ROOT.mkdir(exist_ok=True)
CONF = ROOT / "rsyslog.conf"
PID = ROOT / "rsyslogd.pid"
LOG = ROOT / "net.log"

IERR = ("<9>Oct 20 07:30:04 10.1.5.150 ipmi: Health EventLog | 2026/10/20 07:30:04 "
        "| 10.1.5.150 | Critical | IERR - Assertion | Processor(OEM)")
INFO = ("<14>Oct 21 14:07:49 10.1.5.150 ipmi: Maintenance EventLog | 2026/10/21 14:07:49 "
        "| 10.1.5.150 | Information | Web logout was successful. | WEB ADMIN(ADMIN)")

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


CONF.write_text(f"""\
global(workDirectory="{ROOT}")
module(load="imudp")
module(load="ommail")
template(name="AlertSubject" type="string"
         string="[syslog] %$.name%: %msg:R,ERE,1,FIELD:[|] (Critical|Warning) [|]--end% %msg:R,ERE,2,FIELD:[|] (Critical|Warning) [|] ([^|]*[^| ])--end%")
template(name="AlertBody" type="string"
         string="%timegenerated:::date-rfc3339% %fromhost-ip% (%$.name%)\\r\\n%rawmsg%\\r\\n")
ruleset(name="remote-net") {{
    set $.name = "bmc.big-storage";
    action(type="omfile" file="{LOG}")
    if $msg contains "Health EventLog" and
       ($msg contains "| Critical |" or $msg contains "| Warning |") then {{
        action(type="ommail" server="127.0.0.1" port="15025"
               mailfrom="rsyslog@probe" mailto="alerts@probe"
               subject.template="AlertSubject" template="AlertBody"
               action.execOnlyOnceEveryInterval="5"
               queue.type="LinkedList" queue.size="1000"
               action.resumeRetryCount="-1" action.resumeInterval="2")
    }}
}}
input(type="imudp" port="15514" address="127.0.0.1" ruleset="remote-net")
""")

check = subprocess.run(["rsyslogd", "-N1", "-f", str(CONF)], capture_output=True, text=True)
print("rsyslogd -N1 rc", check.returncode,
      [l for l in check.stderr.splitlines() if "error" in l.lower()])


def send(msg: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg.encode(), ("127.0.0.1", 15514)); s.close()


server = socket.socket(); server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 15025)); server.listen()
stop = threading.Event()
sink = threading.Thread(target=smtp_sink, args=(stop, server)); sink.start()
daemon = subprocess.Popen(["rsyslogd", "-n", "-f", str(CONF), "-i", str(PID)])
time.sleep(1.5)
try:
    send(IERR); send(IERR); send(INFO)
    time.sleep(3)
    print(f"phase 1: {len(mails)} mail(s) for IERR, IERR(dup within 5s), INFO")
    for m in mails:
        print("-----\n" + m.strip())
    stop.set(); sink.join(); server.close()   # SMTP now down
    time.sleep(6)                              # past the 5s interval
    before = LOG.read_text().count("\n")
    send(IERR)
    time.sleep(2)
    after = LOG.read_text().count("\n")
    print(f"phase 2 (SMTP down): log lines {before} -> {after} "
          f"({'written' if after > before else 'BLOCKED'})")
finally:
    daemon.send_signal(signal.SIGTERM)
    daemon.wait(timeout=15)
