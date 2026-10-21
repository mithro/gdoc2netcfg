"""READ-ONLY: predict which live /var/log/<net>/*.log files a deploy renames.

Matches each current (unrotated) remote log file to the name the generated
sender-name table would give the same device, so the PR can say up front
which histories split. A current file is matched by its stem as:
  - an IP in the table            (BMCs etc. that send no header hostname)
  - a table name                  (already right: no change)
  - a table name's bare host part (e.g. au-plug-1 -> au-plug-1.iot)
  - a table name + "-1"           (switch sysnames)
  - ipv4.<name>.<net>.<domain>    (PTR-named files)
Anything else is printed as UNMATCHED for a human to look at.

Usage (worktree root, after `generate rsyslog --output-dir tmp/out` from /opt):
  uv run python tmp/predict_renames.py tmp/out/etc/rsyslog.d/remote-logs.names.json
"""

import json
import pathlib
import re
import sys

NETS = ("net", "iot", "wifi", "int", "sm", "pwr", "store", "roam")
ROTATED = re.compile(r"\.log\.\d+(\.gz)?$")

table = json.loads(pathlib.Path(sys.argv[1]).read_text())
by_ip = {row["index"]: row["value"] for row in table["table"]}
names = set(by_ip.values())


def predict(stem: str) -> str | None:
    if stem in by_ip:
        return by_ip[stem]
    if stem in names:
        return stem
    m = re.fullmatch(r"ipv4\.(.+)\.(?:" + "|".join(NETS) + r")\.welland\.mithis\.com", stem)
    if m and m.group(1) in names:
        return m.group(1)
    for candidate in (stem, stem.removesuffix("-1")):
        hits = sorted(n for n in names if n == candidate or n.split(".")[0] == candidate)
        if len(hits) == 1:
            return hits[0]
    return None


for net in NETS:
    d = pathlib.Path("/var/log") / net
    if not d.is_dir():
        continue
    for f in sorted(d.iterdir()):
        if not f.name.endswith(".log") or ROTATED.search(f.name):
            continue
        kernel = f.name.endswith(".kernel.log")
        stem = f.name.removesuffix(".kernel.log" if kernel else ".log")
        new = predict(stem)
        suffix = ".kernel.log" if kernel else ".log"
        if new is None:
            print(f"UNMATCHED {net}/{f.name}")
        elif new + suffix != f.name:
            print(f"rename    {net}/{f.name} -> {net}/{new}{suffix}")
        else:
            print(f"same      {net}/{f.name}")
