#!/usr/bin/env python3
"""Generate a STATIC mockup of the Power Plugs dashboard using REAL fleet data.

Pulls live state (online/relay/load) from HA REST, real energy-window numbers
from recorder/statistics_during_period (WS), and plug list + 'controls' from the
IoT sheet. Emits a self-contained HTML snapshot styled like the existing
reachability/switch dashboards. NOT live (no WebSocket/toggle) — a preview only.
"""
import asyncio
import csv
import html
import json
import re
import urllib.request
from datetime import datetime, timedelta, timezone

import websockets
from gdoc2netcfg.config import load_config

CSV_PATH = "/opt/gdoc2netcfg/.cache/iot.csv"
cfg = load_config()
DOMAIN = cfg.site.domain
ws_url = (cfg.homeassistant.url.rstrip("/")
          .replace("http://", "ws://").replace("https://", "wss://") + "/api/websocket")


def resolve_ip(sheet_ip):
    p = sheet_ip.strip().split(".")
    if len(p) == 4 and p[1] == "X":
        p[1] = "1"
    return ".".join(p)


def load_plugs():
    out = []
    with open(CSV_PATH, newline="") as f:
        for row in csv.DictReader(f):
            m = (row.get("Machine") or "").strip()
            if not re.fullmatch(r"(au|us)-plug-\d+", m):
                continue
            site = (row.get("Site") or "").strip()
            if site and site != "Welland":
                continue
            ctrl = (row.get("Controls") or "").strip()
            controls = [c.strip() for c in re.split(r"[/,;\n\r]+", ctrl) if c.strip()]
            out.append({
                "machine": m,
                "topic": m.replace("-", "_"),
                "nid": m.replace("-", "_") + "_iot",
                "fqdn": f"{m}.iot.{DOMAIN}",
                "ipv4_sheet": resolve_ip(row.get("IP") or ""),
                "controls": controls,
            })
    fam = {"au": 0, "us": 1}
    out.sort(key=lambda p: (fam[p["machine"][:2]], int(p["machine"].rsplit("-", 1)[1])))
    seen, dedup = set(), []
    for p in out:
        if p["machine"] not in seen:
            seen.add(p["machine"]); dedup.append(p)
    return dedup


def fetch_states():
    req = urllib.request.Request(
        f"{cfg.homeassistant.url.rstrip('/')}/api/states",
        headers={"Authorization": f"Bearer {cfg.homeassistant.token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return {s["entity_id"]: s for s in json.loads(r.read())}


async def fetch_stats(topics):
    ids = [f"sensor.{t}_energy_total" for t in topics]
    async with websockets.connect(ws_url, max_size=40 * 1024 * 1024) as ws:
        await ws.recv()
        await ws.send(json.dumps({"type": "auth", "access_token": cfg.homeassistant.token}))
        if json.loads(await ws.recv()).get("type") != "auth_ok":
            raise SystemExit("auth failed")
        now = datetime.now(timezone.utc)
        mid = 1
        async def q(period, start):
            nonlocal mid
            await ws.send(json.dumps({"id": mid, "type": "recorder/statistics_during_period",
                "start_time": start.isoformat(), "statistic_ids": ids, "period": period}))
            want = mid; mid += 1
            while True:
                m = json.loads(await ws.recv())
                if m.get("id") == want:
                    return m["result"]
        five = await q("5minute", now - timedelta(minutes=65))
        hour = await q("hour", now - timedelta(hours=25))
        return five, hour


def windows(topic, five, hour):
    """Return (rate5m, rate1h, rate24h) W and (e1h, e24h) kWh, or None each."""
    sid = f"sensor.{topic}_energy_total"
    f = five.get(sid, []) or []
    h = hour.get(sid, []) or []
    def chg(b):
        return b.get("change") if b.get("change") is not None else 0.0
    r5 = e1 = r1 = e24 = r24 = None
    if f:
        r5 = chg(f[-1]) / (5/60) * 1000
        last12 = f[-12:]
        e1 = sum(chg(b) for b in last12)
        r1 = e1 * 1000  # kWh over 1h -> W
    if h:
        last24 = h[-24:]
        e24 = sum(chg(b) for b in last24)
        r24 = e24 / 24 * 1000
    return r5, r1, r24, e1, e24


def st(states, eid):
    s = states.get(eid)
    return s["state"] if s else None


def fetch_history(eids, days=14):
    """REST recorder history for the given entity_ids over the last `days`."""
    if not eids:
        return {}
    from urllib.parse import quote
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    url = (f"{cfg.homeassistant.url.rstrip('/')}/api/history/period/{start.isoformat()}"
           f"?filter_entity_id={quote(','.join(eids))}"
           f"&end_time={quote(end.isoformat())}&minimal_response&no_attributes")
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {cfg.homeassistant.token}"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read())
    out = {}
    for series in data:
        if series:
            out[series[0].get("entity_id")] = series
    return out


def last_seen_from_history(series):
    """Last online->offline transition (connectivity on->off) = last seen, or None.

    Uses the transition (not the latest 'off') so an HA restart that re-publishes
    'off' (prev already 'off') is ignored.
    """
    if not series:
        return None
    ts = None
    prev = None
    for e in series:
        state = e.get("state")
        if state == "off" and prev == "on":
            ts = e.get("last_changed") or e.get("last_updated")
        prev = state
    if ts is None:
        return None
    try:
        return (datetime.fromtimestamp(ts, timezone.utc)
                if isinstance(ts, (int, float)) else datetime.fromisoformat(ts))
    except (ValueError, TypeError, OSError):
        return None


def ago(dt):
    """Relative 'X <unit> ago' from an aware datetime to now."""
    s = int((datetime.now(timezone.utc) - dt).total_seconds())
    s = max(s, 0)
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute"), (1, "second")):
        if s >= size:
            n = s // size
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return "just now"


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fmt_w(v):
    if not isinstance(v, (int, float)):
        return "—"
    cls = ' class="z"' if round(v) == 0 else ""
    return f'<span{cls}>{v:.0f}&nbsp;W</span>'


def fmt_kwh(v):
    # Fixed 3 decimals so decimal points line up under right-alignment.
    if not isinstance(v, (int, float)):
        return "—"
    cls = ' class="z"' if round(v, 3) == 0 else ""
    return f'<span{cls}>{v:.3f}&nbsp;kWh</span>'


def nodeid(name):
    return re.sub(r"[^a-zA-Z0-9]", "_", name).lower()


def controls_cell(controls, directory, states, domain, relay=None, flag_empty=False):
    """Controls as a list; per-device icon is relay-aware.

    - online + plug ON   -> green (expected)
    - online + plug OFF  -> warning (powered despite the plug being off)
    - offline + plug ON  -> red (should be powered but isn't)
    - offline + plug OFF -> white circle + greyed (expected off)

    flag_empty: plug is drawing power but Controls is blank -> data-quality warning.
    """
    if not controls:
        if flag_empty:
            return ('<td class="ctrl"><span class="warn" title="Drawing power but no '
                    'controlled device recorded">❗ unlisted load</span></td>')
        return '<td class="ctrl"><span class="offdot">—</span></td>'
    plug_off = relay == "off"
    items = []
    for c in controls:
        name = html.escape(c)
        host = directory.get(c)
        if not host:
            items.append(f'<div><span class="offdot">• {name}</span></div>')
            continue
        conn = states.get(f"binary_sensor.gdoc2netcfg_{nodeid(host)}_connectivity")
        link = f"http://ipv4.{host}.{domain}"
        cls, title = "", ""
        if conn is None:
            icon = '<span class="offdot">•</span>'
        elif conn["state"] == "on":
            if plug_off:
                icon = '⚠️'; title = ' title="Online but its plug is OFF"'
            else:
                icon = '\U0001F7E2'
        elif relay == "on":
            icon = '\U0001F534'; title = ' title="Offline but plug is ON"'
        else:
            icon = '⚪'; cls = "dim"
            title = (' title="Offline (plug is off)"' if plug_off
                     else ' title="Offline (plug state unknown)"')
        items.append(f'<div class="{cls}"{title}>{icon} <a href="{link}">{name}</a></div>')
    return f'<td class="ctrl">{"".join(items)}</td>'


def example_rows():
    """Synthetic rows exercising every visual state (a legend)."""
    G, R, W, WARN, BANG = '\U0001F7E2', '\U0001F534', '⚪', '⚠️', '❗'

    def dev(icon, name, cls="", title=""):
        c = f' class="{cls}"' if cls else ""
        t = f' title="{title}"' if title else ""
        return f'<div{c}{t}>{icon} <a href="#">{name}</a></div>'

    def ctrl(inner):
        return f'<td class="ctrl">{inner}</td>'

    on_g = '<span class="on">\U0001F7E2 online</span>'

    def off(seen):
        return (f'<span class="red">\U0001F534 offline</span>'
                f'<div class="seen">last seen {seen}</div>')

    pwr_on = '<span class="toggle on">\U0001F7E2 ON</span>'
    pwr_off = '<span class="toggle offdot">⚪ OFF</span>'
    pwr_na = '<span class="toggle offdot">—</span>'
    none_ctrl = '<td class="ctrl"><span class="offdot">—</span></td>'
    unlisted = ('<td class="ctrl"><span class="warn" title="Drawing power but no '
                f'controlled device recorded">{BANG} unlisted load</span></td>')

    def row(label, online, power, controls, load, r5, r1, r24, e1, e24, today):
        return (f'<tr><td><b>{label}</b></td>'
                f'<td><span class="offdot">—</span></td>'
                f'<td>{online}</td><td>{power}</td>{controls}'
                f'<td class="n load">{fmt_w(load)}</td>'
                f'<td class="n grp">{fmt_w(r5)}</td><td class="n">{fmt_w(r1)}</td>'
                f'<td class="n">{fmt_w(r24)}</td>'
                f'<td class="n grp">{fmt_kwh(e1)}</td><td class="n">{fmt_kwh(e24)}</td>'
                f'<td class="n">{fmt_kwh(today)}</td></tr>')

    return "".join([
        row("online · on · drawing", on_g, pwr_on, ctrl(dev(G, "server-a")),
            42, 40, 41, 39, 0.041, 0.98, 0.30),
        row("relay off (standby)", on_g, pwr_off,
            ctrl(dev(W, "server-d", "dim", "Offline (plug is off)")),
            0, 0, 0, 0, 0, 0, 0),
        row("⚠ device on, plug off", on_g, pwr_off,
            ctrl(dev(WARN, "server-b", "", "Online but its plug is OFF")),
            0, 0, 0, 0, 0, 0, 0),
        row("\U0001F534 device off, plug on", on_g, pwr_on,
            ctrl(dev(R, "server-c", "", "Offline but plug is ON")),
            6, 5, 6, 6, 0.006, 0.14, 0.05),
        row("❗ unlisted load", on_g, pwr_on, unlisted,
            30, 29, 30, 28, 0.030, 0.70, 0.22),
        row("other controls", on_g, pwr_on,
            ctrl('<div><span class="offdot">• unknown-host</span></div>'
                 '<div><span class="offdot">• Some Free Text</span></div>'),
            12, 11, 12, 12, 0.012, 0.28, 0.09),
        row("plug offline (recent)", off("5 minutes ago"), pwr_na,
            ctrl(dev(W, "server-e", "dim", "Offline (plug state unknown)")),
            None, None, None, None, None, None, None),
        row("plug offline (&gt;14d)", off("&gt;14 days ago"), pwr_na, none_ctrl,
            None, None, None, None, None, None, None),
        row("plug offline (no history)", off("unknown"), pwr_na, none_ctrl,
            None, None, None, None, None, None, None),
    ])


CSS = """
:root{--bg:#111;--text:#e1e1e1;--text2:#9b9b9b;--div:#3a3a3a;--hover:#2a2a2a;--link:#4fc3f7;}
body{font-family:Roboto,Noto,sans-serif;margin:16px;background:var(--bg);color:var(--text);font-size:14px;}
h1{font-size:1.3em;margin:0 0 2px;}
h2{font-size:1.05em;margin:20px 0 6px;color:var(--text2);border-bottom:1px solid var(--div);padding-bottom:3px;}
.note{color:var(--text2);font-size:0.85em;margin-bottom:12px;}
.note b{color:#ffb74d;}
table{border-collapse:collapse;font-size:0.85em;}
th{text-align:left;padding:5px 8px;border-bottom:2px solid var(--div);color:var(--text2);white-space:nowrap;cursor:pointer;}
th.r,td.r{text-align:right;}
td{padding:4px 8px;white-space:nowrap;border-bottom:1px solid #1c1c1c;vertical-align:middle;}
tr.off{opacity:0.55;}
a{color:var(--link);text-decoration:none;}
.on{color:#66bb6a;} .offdot{color:#9b9b9b;} .red{color:#ef5350;}
.seen{font-size:0.78em;color:var(--text2);}
.toggle{display:inline-block;min-width:52px;box-sizing:border-box;text-align:center;cursor:pointer;border:1px solid var(--div);border-radius:4px;padding:1px 6px;user-select:none;}
.z{color:#666;}
.ctrl{color:#ce93d8;}
.ctrl div{white-space:nowrap;}
.ctrl a{color:var(--link);}
.ctrl .dim{opacity:0.5;}
.warn{color:#ffb74d;}
.load{color:#fff;}
td.n{padding:3px 6px;text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;font-size:0.85em;}
th.n{padding:3px 6px;text-align:right;}
.grp{border-left:1px solid var(--div);}
th.grphdr{text-align:center;border-left:1px solid var(--div);padding:5px 6px;}
tfoot td{border-top:2px solid var(--div);color:var(--text2);font-weight:bold;padding-top:8px;}
"""


def main():
    plugs = load_plugs()
    states = fetch_states()
    five, hour = asyncio.run(fetch_stats([p["topic"] for p in plugs]))

    # Last-seen for offline plugs: from recorder history (survives HA restart).
    offline_conn = [
        f"binary_sensor.gdoc2netcfg_{p['nid']}_connectivity"
        for p in plugs
        if st(states, f"binary_sensor.gdoc2netcfg_{p['nid']}_connectivity") != "on"
    ]
    hist = fetch_history(offline_conn, days=14)
    seen_map = {eid: last_seen_from_history(series) for eid, series in hist.items()}

    # Host directory (machine -> hostname) for resolving controlled devices.
    dd = states.get("sensor.gdoc2netcfg_host_directory")
    _meta = {"friendly_name", "icon", "unit_of_measurement", "device_class"}
    directory = {k: v for k, v in (dd.get("attributes", {}) if dd else {}).items()
                 if k not in _meta and isinstance(v, str)}

    rows = []
    tot_load = 0.0
    tot_e24 = 0.0
    n_online = n_on = 0
    for p in plugs:
        t, nid = p["topic"], p["nid"]
        conn_eid = f"binary_sensor.gdoc2netcfg_{nid}_connectivity"
        online = st(states, conn_eid)
        relay = st(states, f"switch.{t}")
        load = num(st(states, f"sensor.{t}_energy_power"))
        volt = num(st(states, f"sensor.{t}_energy_voltage"))
        pf = num(st(states, f"sensor.{t}_energy_factor"))
        today = num(st(states, f"sensor.{t}_energy_today"))
        ipv4 = st(states, f"sensor.gdoc2netcfg_{nid}_default_ipv4") or p["ipv4_sheet"]
        r5, r1, r24, e1, e24 = windows(t, five, hour)

        is_online = online == "on"
        if is_online:
            n_online += 1
        if relay == "on":
            n_on += 1
            if isinstance(load, (int, float)):
                tot_load += load
        if isinstance(e24, (int, float)):
            tot_e24 += e24

        link = f"http://ipv4.{p['fqdn']}"
        if is_online:
            on_cell = '<span class="on">\U0001F7E2 online</span>'
        else:
            if conn_eid not in states:
                seen_txt = '<div class="seen">last seen unknown</div>'
            else:
                seen = seen_map.get(conn_eid)
                seen_txt = (f'<div class="seen">last seen {ago(seen)}</div>' if seen
                            else '<div class="seen">last seen &gt;14 days ago</div>')
            on_cell = f'<span class="red">\U0001F534 offline</span>{seen_txt}'
        if relay == "on":
            toggle = '<span class="toggle on">\U0001F7E2 ON</span>'
        elif relay == "off":
            toggle = '<span class="toggle offdot">⚪ OFF</span>'
        else:
            toggle = '<span class="toggle offdot">—</span>'
        load_title = ""
        if isinstance(volt, (int, float)):
            load_title = f' title="{volt:.0f} V, PF {pf if pf is not None else "?"}"'
        drawing = (any(isinstance(v, (int, float)) and v > 0 for v in (load, r5, r1, r24))
                   or any(isinstance(v, (int, float)) and v > 0.0005 for v in (e1, e24, today)))
        controls_td = controls_cell(p["controls"], directory, states, DOMAIN,
                                    relay=relay, flag_empty=drawing)

        rows.append(f"""<tr class="{'' if is_online else 'off'}">
<td><a href="{link}">{html.escape(p['machine'])}</a></td>
<td><a href="http://{ipv4}">{html.escape(ipv4)}</a></td>
<td>{on_cell}</td>
<td>{toggle}</td>
{controls_td}
<td class="n load"{load_title}>{fmt_w(load)}</td>
<td class="n grp">{fmt_w(r5)}</td><td class="n">{fmt_w(r1)}</td><td class="n">{fmt_w(r24)}</td>
<td class="n grp">{fmt_kwh(e1)}</td><td class="n">{fmt_kwh(e24)}</td><td class="n">{fmt_kwh(today)}</td>
</tr>""")

    thead_html = (
        '<thead>'
        '<tr>'
        '<th rowspan="2">Plug</th><th rowspan="2">IP</th><th rowspan="2">Online</th>'
        '<th rowspan="2">Power</th><th rowspan="2">Controls</th>'
        '<th rowspan="2" class="n">Load</th>'
        '<th colspan="3" class="grphdr">Rate</th>'
        '<th colspan="3" class="grphdr">Energy</th>'
        '</tr>'
        '<tr>'
        '<th class="n grp">5m</th><th class="n">1h</th><th class="n">24h</th>'
        '<th class="n grp">1h</th><th class="n">24h</th><th class="n">today</th>'
        '</tr>'
        '</thead>'
    )
    snap = datetime.now().strftime("%Y-%m-%d %H:%M")
    foot = (f'<tr><td colspan="5">{len(plugs)} plugs &middot; {n_online} online &middot; '
            f'{n_on} relay ON</td>'
            f'<td class="n load">{tot_load:.0f}&nbsp;W</td>'
            f'<td class="n grp"></td><td class="n"></td><td class="n"></td>'
            f'<td class="n grp"></td><td class="n">{tot_e24:.3f}&nbsp;kWh</td><td class="n"></td>'
            f'</tr>')

    htmlout = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{CSS}</style></head>
<body>
<h1>\U0001F50C Power Plugs</h1>
<div class="note"><b>MOCKUP — static snapshot {snap}</b> (real fleet data). In the live dashboard:
columns are click-to-sort, Power is a working toggle (with confirm), and all values update in real time via HA WebSocket.</div>
<h2>Examples — all states (illustrative, not real devices)</h2>
<table>{thead_html}
<tbody>
{example_rows()}
</tbody>
</table>
<h2>Welland fleet</h2>
<table>{thead_html}
<tbody>
{''.join(rows)}
</tbody>
<tfoot>{foot}</tfoot>
</table>
</body></html>"""

    out = "/home/tim/github/mithro/gdoc2netcfg/tmp/power-plugs-mockup.html"
    with open(out, "w") as f:
        f.write(htmlout)
    print(f"wrote {out}  ({len(plugs)} plugs, {n_online} online)")


if __name__ == "__main__":
    main()
