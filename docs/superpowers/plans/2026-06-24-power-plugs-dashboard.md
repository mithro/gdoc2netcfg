# Power Plugs Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a standalone Home Assistant "Power Plugs" dashboard listing every au-plug/us-plug Tasmota smart plug with identity, reachability (+relative last-seen), relay toggle, live load, windowed energy rate/total, and a relay-aware linked list of what each plug powers.

**Architecture:** Extend the existing `scripts/ha-create-reachability-dashboard.py` (which already generates two dashboards) with a third. Python bakes per-plug *structural* JSON into a new self-contained HTML template; the page reads *live* state over the HA WebSocket and computes energy windows via `recorder/statistics_during_period` and last-seen via `history/history_during_period`. Deployed as its own Lovelace dashboard.

**Tech Stack:** Python 3.11+ (stdlib + `websockets`), the `gdoc2netcfg` pipeline, vanilla JS + HA WebSocket API, headless `chromium` only for local preview.

## Global Constraints

- Run Python via `uv run` only; never bare `python`/`pip`.
- Fail loud, never fabricate: if an expected entity is missing, warn to stderr — never bake a dead/guessed entity_id or synthetic value.
- Small, discrete commits per task. `uv run ruff check src/ tests/ scripts/` must pass; `uv run pytest` must pass.
- Welland-only feature (monarto has no `[homeassistant]`); no monarto handling.
- The committed mockup is the visual source of truth: `docs/superpowers/specs/2026-06-24-power-plugs-dashboard-mockup.html` (+ `.png`, `.gen.py`). When unsure about layout/markup/CSS, copy from it.
- `node_id(x)` means `re.sub(r"[^a-zA-Z0-9]", "_", x).lower()` — the existing `_node_id` helper in the generator.
- Controls come pre-parsed from `host.tasmota_data.controls` (a tuple, already split on comma/newline by `supplements/tasmota.py`). Do not re-split.

## File Structure

- `scripts/ha-create-reachability-dashboard.py` — **modify**: add plug functions + constants + wire into `main()`. (Existing generator; functions live here for consistency with the other two dashboards.)
- `scripts/ha-plug-dashboard.html` — **create**: the new self-contained template (CSS from the mockup + live-WebSocket JS).
- `tests/test_scripts/test_plug_dashboard.py` — **create**: pytest for the new pure Python functions (loads the dash-named script via `importlib`).
- `tests/test_scripts/__init__.py` — **create** if missing (empty).

---

### Task 1: Plug selection + structural data builder (pure Python, TDD)

**Files:**
- Modify: `scripts/ha-create-reachability-dashboard.py` (add helpers near the other `_build_*` helpers, before `# Main`)
- Create: `tests/test_scripts/__init__.py`
- Create: `tests/test_scripts/test_plug_dashboard.py`

**Interfaces:**
- Consumes: existing `_node_id(name)` in the script; `Host` objects from the pipeline exposing `.machine_name`, `.hostname`, `.first_ipv4`, `.tasmota_data` (with `.mqtt_topic: str`, `.controls: tuple[str,...]`).
- Produces:
  - `_is_plug(machine_name: str) -> bool`
  - `_select_plug_hosts(hosts: list) -> list` (tasmota-enriched hosts whose machine_name is a plug, sorted by family then number)
  - `_build_plug_data(host, domain: str) -> dict` returning keys `machine, topic, nid, fqdn, ipv4, controls` (controls = `list[str]`)

- [ ] **Step 1: Create the test package marker**

Create `tests/test_scripts/__init__.py` (empty file).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_scripts/test_plug_dashboard.py`:

```python
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ha-create-reachability-dashboard.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("ha_dash_gen", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _host(machine, hostname, topic, controls=(), ipv4="10.1.91.10"):
    return SimpleNamespace(
        machine_name=machine,
        hostname=hostname,
        first_ipv4=ipv4,
        tasmota_data=SimpleNamespace(mqtt_topic=topic, controls=tuple(controls)),
    )


def test_is_plug(mod):
    assert mod._is_plug("au-plug-10")
    assert mod._is_plug("us-plug-2")
    assert not mod._is_plug("au-plug")       # no number
    assert not mod._is_plug("ir-ac-remote")  # not a plug
    assert not mod._is_plug("big-storage")


def test_select_plug_hosts_filters_and_sorts(mod):
    hosts = [
        _host("us-plug-2", "us-plug-2", "us_plug_2"),
        _host("au-plug-2", "au-plug-2.iot", "au-plug-2"),
        _host("au-plug-10", "au-plug-10.iot", "au-plug-10"),
        SimpleNamespace(machine_name="ir-ac-remote", hostname="ir-ac-remote",
                        first_ipv4=None, tasmota_data=SimpleNamespace(
                            mqtt_topic="ir-ac-remote", controls=())),
        SimpleNamespace(machine_name="big-storage", hostname="big-storage",
                        first_ipv4=None, tasmota_data=None),  # not tasmota
    ]
    out = mod._select_plug_hosts(hosts)
    assert [h.machine_name for h in out] == ["au-plug-2", "au-plug-10", "us-plug-2"]


def test_build_plug_data(mod):
    h = _host("au-plug-10", "au-plug-10.iot", "au-plug-10",
              controls=("rpiz-dash-1", "sw-bb-25g"), ipv4="10.1.91.10")
    d = mod._build_plug_data(h, "welland.mithis.com")
    assert d == {
        "machine": "au-plug-10",
        "topic": "au_plug_10",
        "nid": "au_plug_10_iot",
        "fqdn": "au-plug-10.iot.welland.mithis.com",
        "ipv4": "10.1.91.10",
        "controls": ["rpiz-dash-1", "sw-bb-25g"],
    }


def test_build_plug_data_no_ipv4(mod):
    h = _host("au-plug-99", "au-plug-99.iot", "au-plug-99", ipv4=None)
    assert mod._build_plug_data(h, "welland.mithis.com")["ipv4"] == ""
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `uv run pytest tests/test_scripts/test_plug_dashboard.py -v`
Expected: FAIL — `AttributeError: module 'ha_dash_gen' has no attribute '_is_plug'`.

- [ ] **Step 4: Implement the helpers**

In `scripts/ha-create-reachability-dashboard.py`, after the `_build_host_data` function (and before the `# Main` section), add:

```python
# ---------------------------------------------------------------------------
# Power Plugs dashboard — structural data
# ---------------------------------------------------------------------------

_PLUG_RE = re.compile(r"(au|us)-plug-(\d+)")


def _is_plug(machine_name: str) -> bool:
    """True for au-plug-<n> / us-plug-<n> machine names."""
    return _PLUG_RE.fullmatch(machine_name) is not None


def _select_plug_hosts(hosts: list) -> list:
    """Tasmota-enriched plug hosts, sorted by family (au, us) then number."""
    plugs = [h for h in hosts if h.tasmota_data is not None and _is_plug(h.machine_name)]
    fam = {"au": 0, "us": 1}
    return sorted(
        plugs,
        key=lambda h: (
            fam[_PLUG_RE.fullmatch(h.machine_name).group(1)],
            int(_PLUG_RE.fullmatch(h.machine_name).group(2)),
        ),
    )


def _build_plug_data(host, domain: str) -> dict:
    """Structural JSON for one plug (no live state — JS reads that at runtime)."""
    first_ip = host.first_ipv4
    return {
        "machine": host.machine_name,
        "topic": _node_id(host.tasmota_data.mqtt_topic),
        "nid": _node_id(host.hostname),
        "fqdn": f"{host.hostname}.{domain}",
        "ipv4": str(first_ip) if first_ip else "",
        "controls": list(host.tasmota_data.controls),
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_scripts/test_plug_dashboard.py -v`
Expected: PASS (4 passed).

- [ ] **Step 6: Lint + commit**

```bash
uv run ruff check scripts/ tests/
git add scripts/ha-create-reachability-dashboard.py tests/test_scripts/
git commit -m "feat(plugs): plug selection + structural data builder for the Power Plugs dashboard"
```

---

### Task 2: Generation-time entity verification (pure Python, TDD)

**Files:**
- Modify: `scripts/ha-create-reachability-dashboard.py`
- Modify: `tests/test_scripts/test_plug_dashboard.py`

**Interfaces:**
- Consumes: plug dicts from `_build_plug_data` (uses the `topic` and `machine` keys); the HA states list (`list[dict]` with `entity_id`), as returned by the existing `_fetch_ha_states`.
- Produces: `_verify_plug_entities(plugs: list[dict], ha_states: list[dict]) -> list[str]` — returns a list of human-readable warning strings (one per plug missing its relay or power entity) and prints each to stderr. Does not raise (a missing entity is a data-quality warning, not a crash — the row still renders with blanks at runtime).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_scripts/test_plug_dashboard.py`:

```python
def test_verify_plug_entities_warns_on_missing(mod, capsys):
    plugs = [
        {"machine": "au-plug-10", "topic": "au_plug_10"},
        {"machine": "au-plug-99", "topic": "au_plug_99"},  # entities absent
    ]
    states = [
        {"entity_id": "switch.au_plug_10"},
        {"entity_id": "sensor.au_plug_10_energy_power"},
    ]
    warnings = mod._verify_plug_entities(plugs, states)
    assert len(warnings) == 1
    assert "au-plug-99" in warnings[0]
    assert "au-plug-99" in capsys.readouterr().err


def test_verify_plug_entities_all_present(mod):
    plugs = [{"machine": "au-plug-10", "topic": "au_plug_10"}]
    states = [
        {"entity_id": "switch.au_plug_10"},
        {"entity_id": "sensor.au_plug_10_energy_power"},
    ]
    assert mod._verify_plug_entities(plugs, states) == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_scripts/test_plug_dashboard.py::test_verify_plug_entities_warns_on_missing -v`
Expected: FAIL — `_verify_plug_entities` not defined.

- [ ] **Step 3: Implement**

In `scripts/ha-create-reachability-dashboard.py`, add after `_build_plug_data`:

```python
def _verify_plug_entities(plugs: list[dict], ha_states: list[dict]) -> list[str]:
    """Warn (stderr) for any plug whose relay or power entity is absent in HA.

    Fail-loud, but non-fatal: the row still renders with blanks at runtime.
    """
    have = {e["entity_id"] for e in ha_states}
    warnings = []
    for p in plugs:
        missing = [
            eid for eid in (f"switch.{p['topic']}", f"sensor.{p['topic']}_energy_power")
            if eid not in have
        ]
        if missing:
            msg = f"plug {p['machine']}: missing HA entities {missing}"
            warnings.append(msg)
            print(f"  warning: {msg}", file=sys.stderr)
    return warnings
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/test_scripts/test_plug_dashboard.py -v`
Expected: PASS (6 passed).

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check scripts/ tests/
git add scripts/ha-create-reachability-dashboard.py tests/test_scripts/test_plug_dashboard.py
git commit -m "feat(plugs): warn on plugs with missing HA relay/power entities"
```

---

### Task 3: The Power Plugs HTML/JS template

**Files:**
- Create: `scripts/ha-plug-dashboard.html`

No pytest (frontend, manually verified after Task 4 deploys it). Create the file with the exact content below. It mirrors the committed mockup's CSS/markup and adapts the WebSocket/sort plumbing from `scripts/ha-switch-dashboard.html`, adding: `recorder/statistics_during_period` energy windows (Σchange), `history/history_during_period` last-seen, relay-aware Controls resolution via `sensor.gdoc2netcfg_host_directory`, greyed zeros, and a confirm-guarded toggle. The static "Examples" legend is baked into the template.

- [ ] **Step 1: Create `scripts/ha-plug-dashboard.html`**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Power Plugs</title>
<script>
function applyTheme(){
  try{
    var bg = window.parent.getComputedStyle(window.parent.document.body).backgroundColor;
    var m = bg.match(/(\d+)/g);
    if(m && m.length >= 3){
      var lum = (0.299*m[0] + 0.587*m[1] + 0.114*m[2]) / 255;
      document.documentElement.classList.toggle("light", lum > 0.5);
    }
  }catch(e){}
}
applyTheme(); setTimeout(applyTheme, 1000);
</script>
<style>
:root{--bg:#111;--text:#e1e1e1;--text2:#9b9b9b;--div:#3a3a3a;--hover:#2a2a2a;--link:#4fc3f7;}
:root.light{--bg:#fafafa;--text:#212121;--text2:#727272;--div:#e0e0e0;--hover:#f0f0f0;--link:#03a9f4;}
body{font-family:Roboto,Noto,sans-serif;margin:16px;background:var(--bg);color:var(--text);font-size:14px;}
h1{font-size:1.3em;margin:0 0 2px;}
h2{font-size:1.05em;margin:20px 0 6px;color:var(--text2);border-bottom:1px solid var(--div);padding-bottom:3px;}
#status-bar{color:var(--text2);font-size:0.85em;margin-bottom:12px;}
table{border-collapse:collapse;font-size:0.85em;}
th{text-align:left;padding:5px 8px;border-bottom:2px solid var(--div);color:var(--text2);white-space:nowrap;cursor:pointer;user-select:none;}
th:hover{background:var(--hover);}
th.r,td.r{text-align:right;}
td{padding:4px 8px;white-space:nowrap;border-bottom:1px solid #1c1c1c;vertical-align:middle;}
tr.off{opacity:0.55;}
a{color:var(--link);text-decoration:none;}
.on{color:#66bb6a;} .offdot{color:#9b9b9b;} .red{color:#ef5350;}
.seen{font-size:0.78em;color:var(--text2);}
.toggle{display:inline-block;min-width:52px;box-sizing:border-box;text-align:center;cursor:pointer;border:1px solid var(--div);border-radius:4px;padding:1px 6px;user-select:none;}
.toggle:hover{filter:brightness(1.3);}
.z{color:#666;}
.ctrl{color:#ce93d8;}
.ctrl div{white-space:nowrap;}
.ctrl a{color:var(--link);}
.ctrl .dim{opacity:0.5;}
.warn{color:#ffb74d;}
.load{color:var(--text);}
td.n{padding:3px 6px;text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap;font-size:0.85em;}
th.n{padding:3px 6px;text-align:right;}
.grp{border-left:1px solid var(--div);}
th.grphdr{text-align:center;border-left:1px solid var(--div);padding:5px 6px;}
tfoot td{border-top:2px solid var(--div);color:var(--text2);font-weight:bold;padding-top:8px;}
.sort-active{font-weight:bold;}
</style>
</head>
<body>
<h1>&#x1F50C; Power Plugs</h1>
<div id="status-bar">Connecting&hellip;</div>
<div id="dashboard"></div>
<script>
var PLUGS = __PLUGS_JSON__;
var DOMAIN = "__DOMAIN__";
var HA_WS = "__HA_WS_URL__";
var HA_TOKEN = "__HA_TOKEN__";

var states = {};       // entity_id -> state
var attrs = {};        // entity_id -> attributes (host_directory only)
var win = {};          // topic -> {r5,r1,r24,e1,e24}
var seen = {};         // nid  -> "x ago" | ">14 days ago" | "unknown"
var sortState = {col: "plug", dir: 1};

var GREEN = "🟢", RED = "🔴", WHITE = "⚪",
    WARN = "⚠️", BANG = "❗";

// ---- helpers ----
function nodeId(n){ return n.replace(/[^a-zA-Z0-9]/g, "_").toLowerCase(); }
function st(e){ return states[e]; }
function num(v){ var n = parseFloat(v); return isNaN(n) ? null : n; }

function fmtW(v){
  if(typeof v !== "number") return "—";
  var z = Math.round(v) === 0 ? ' class="z"' : "";
  return '<span'+z+'>'+v.toFixed(0)+'&nbsp;W</span>';
}
function fmtKwh(v){
  if(typeof v !== "number") return "—";
  var z = Math.abs(v) < 0.0005 ? ' class="z"' : "";
  return '<span'+z+'>'+v.toFixed(3)+'&nbsp;kWh</span>';
}
function agoStr(ms){
  var s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  var u = [[86400,"day"],[3600,"hour"],[60,"minute"],[1,"second"]];
  for(var i=0;i<u.length;i++){ if(s>=u[i][0]){ var n=Math.floor(s/u[i][0]); return n+" "+u[i][1]+(n!==1?"s":"")+" ago"; } }
  return "just now";
}

// ---- WebSocket ----
var ws, msgId = 1, connected = false, pending = {}, renderTimer = null;
function setStatus(t){ document.getElementById("status-bar").textContent = t; }
function send(obj, handler){ obj.id = msgId++; if(handler) pending[obj.id] = handler; ws.send(JSON.stringify(obj)); return obj.id; }
function scheduleRender(){ if(renderTimer) return; renderTimer = setTimeout(function(){ renderTimer=null; render(); }, 200); }

function haConnect(){
  ws = new WebSocket(HA_WS);
  ws.onopen = function(){ setStatus("Authenticating…"); };
  ws.onmessage = function(ev){
    var msg = JSON.parse(ev.data);
    if(msg.type === "auth_required"){
      ws.send(JSON.stringify({type:"auth", access_token:HA_TOKEN}));
    } else if(msg.type === "auth_ok"){
      connected = true; setStatus("Fetching state…");
      send({type:"get_states"}, onStates);
      send({type:"subscribe_events", event_type:"state_changed"});
      setInterval(fetchStats, 60000);
      setInterval(fetchLastSeen, 300000);
    } else if(msg.type === "auth_invalid"){
      setStatus("Auth failed: " + (msg.message || "invalid token"));
    } else if(msg.type === "result" && pending[msg.id]){
      var h = pending[msg.id]; delete pending[msg.id]; h(msg);
    } else if(msg.type === "event" && msg.event && msg.event.event_type === "state_changed"){
      var d = msg.event.data;
      if(d.new_state){
        states[d.entity_id] = d.new_state.state;
        if(d.entity_id === "sensor.gdoc2netcfg_host_directory" && d.new_state.attributes)
          attrs[d.entity_id] = d.new_state.attributes;
        scheduleRender();
      }
    }
  };
  ws.onclose = function(){ connected=false; setStatus("Disconnected — reconnecting in 5s…"); setTimeout(haConnect, 5000); };
  ws.onerror = function(){ ws.close(); };
}

function onStates(msg){
  if(!msg.success || !Array.isArray(msg.result)) return;
  for(var i=0;i<msg.result.length;i++){
    var e = msg.result[i];
    states[e.entity_id] = e.state;
    if(e.entity_id === "sensor.gdoc2netcfg_host_directory" && e.attributes)
      attrs[e.entity_id] = e.attributes;
  }
  setStatus("Live — " + PLUGS.length + " plugs");
  fetchStats(); fetchLastSeen(); scheduleRender();
}

// ---- energy windows (statistics) ----
function statIds(){ return PLUGS.map(function(p){ return "sensor."+p.topic+"_energy_total"; }); }
function fetchStats(){
  if(!connected) return;
  var now = Date.now();
  send({type:"recorder/statistics_during_period", period:"5minute",
        start_time:new Date(now - 65*60000).toISOString(), statistic_ids:statIds()},
       function(m){ applyStats(m, "short"); });
  send({type:"recorder/statistics_during_period", period:"hour",
        start_time:new Date(now - 25*3600000).toISOString(), statistic_ids:statIds()},
       function(m){ applyStats(m, "hour"); });
}
function sumChange(buckets, n){
  if(!buckets || !buckets.length) return null;
  var slice = n ? buckets.slice(-n) : buckets, t = 0;
  for(var i=0;i<slice.length;i++){ var c = slice[i].change; if(typeof c === "number") t += c; }
  return t;
}
function applyStats(msg, kind){
  if(!msg.success || !msg.result) return;
  for(var i=0;i<PLUGS.length;i++){
    var p = PLUGS[i], sid = "sensor."+p.topic+"_energy_total", b = msg.result[sid];
    win[p.topic] = win[p.topic] || {};
    var w = win[p.topic];
    if(kind === "short"){
      var last = b && b.length ? b[b.length-1].change : null;
      w.r5 = (typeof last === "number") ? last/(5/60)*1000 : null;
      var e1 = sumChange(b, 12);
      w.e1 = e1; w.r1 = (typeof e1 === "number") ? e1*1000 : null;
    } else {
      var e24 = sumChange(b, 24);
      w.e24 = e24; w.r24 = (typeof e24 === "number") ? e24/24*1000 : null;
    }
  }
  scheduleRender();
}

// ---- last-seen (history) for offline plugs ----
function fetchLastSeen(){
  if(!connected) return;
  var ids = [];
  for(var i=0;i<PLUGS.length;i++){
    var ce = "binary_sensor.gdoc2netcfg_" + PLUGS[i].nid + "_connectivity";
    if(st(ce) !== "on") ids.push(ce);
  }
  if(!ids.length){ scheduleRender(); return; }
  var start = new Date(Date.now() - 14*86400000).toISOString();
  send({type:"history/history_during_period", start_time:start,
        entity_ids:ids, minimal_response:true, no_attributes:true},
       function(m){ applyLastSeen(m); });
}
function applyLastSeen(msg){
  if(!msg.success || !msg.result) return;
  // result keyed by entity_id -> array of {s,lu/lc} (compressed) or {state,last_changed}
  for(var eid in msg.result){
    var arr = msg.result[eid], ts = null, prev = null;
    for(var i=0;i<arr.length;i++){
      var stt = arr[i].s !== undefined ? arr[i].s : arr[i].state;
      if(stt === "off" && prev === "on"){
        var t = (arr[i].lc !== undefined ? arr[i].lc :
                 arr[i].lu !== undefined ? arr[i].lu : arr[i].last_changed);
        ts = (typeof t === "number") ? t*1000 : Date.parse(t);
      }
      prev = stt;
    }
    var nid = eid.replace(/^binary_sensor\.gdoc2netcfg_/, "").replace(/_connectivity$/, "");
    seen[nid] = (ts === null) ? ">14 days ago" : agoStr(ts);
  }
  scheduleRender();
}

// ---- controls (relay-aware) ----
function resolveHost(name){
  var dir = attrs["sensor.gdoc2netcfg_host_directory"];
  var host = dir ? dir[name] : null;
  if(!host) return null;
  var nid = nodeId(host);
  return {host:host, conn:st("binary_sensor.gdoc2netcfg_"+nid+"_connectivity")};
}
function controlsCell(p, relay){
  var td = document.createElement("td"); td.className = "ctrl";
  var hasLoad = (function(){
    var w = win[p.topic] || {};
    return [num(st("sensor."+p.topic+"_energy_power")), w.r5, w.r1, w.r24].some(function(v){ return typeof v==="number" && v>0; })
        || [w.e1, w.e24].some(function(v){ return typeof v==="number" && v>0.0005; });
  })();
  if(!p.controls.length){
    var s = document.createElement("span");
    if(hasLoad){ s.className="warn"; s.title="Drawing power but no controlled device recorded"; s.textContent = BANG+" unlisted load"; }
    else { s.className="offdot"; s.textContent="—"; }
    td.appendChild(s); return td;
  }
  var plugOff = relay === "off";
  p.controls.forEach(function(name){
    var div = document.createElement("div");
    var r = resolveHost(name);
    if(!r){ var b=document.createElement("span"); b.className="offdot"; b.textContent="• "+name; div.appendChild(b); td.appendChild(div); return; }
    var icon, online = r.conn === "on";
    if(r.conn === undefined || r.conn === null || r.conn === "unavailable"){ icon = "•"; }
    else if(online){ icon = plugOff ? WARN : GREEN; if(plugOff) div.title = "Online but its plug is OFF"; }
    else if(relay === "on"){ icon = RED; div.title = "Offline but plug is ON"; }
    else { icon = WHITE; div.className = "dim"; div.title = plugOff ? "Offline (plug is off)" : "Offline (plug state unknown)"; }
    div.insertBefore(document.createTextNode(icon + " "), div.firstChild);
    var a = document.createElement("a"); a.href = "http://ipv4."+r.host+"."+DOMAIN; a.textContent = name;
    div.appendChild(a);
    td.appendChild(div);
  });
  return td;
}

// ---- sorting ----
function natCmp(a,b){
  var ax=String(a).match(/(\d+|\D+)/g)||[], bx=String(b).match(/(\d+|\D+)/g)||[];
  for(var i=0;i<Math.min(ax.length,bx.length);i++){
    var an=parseInt(ax[i],10), bn=parseInt(bx[i],10), isn=!isNaN(an)&&!isNaN(bn);
    var c = isn ? an-bn : ax[i].localeCompare(bx[i]); if(c!==0) return c;
  }
  return ax.length-bx.length;
}
function sortVal(p, col){
  var w = win[p.topic]||{};
  switch(col){
    case "plug": return p.machine;
    case "ip": var v=st("sensor.gdoc2netcfg_"+p.nid+"_default_ipv4")||p.ipv4, x=v.split("."); return x.length===4?(+x[0]*16777216+ +x[1]*65536+ +x[2]*256+ +x[3]):0;
    case "online": return st("binary_sensor.gdoc2netcfg_"+p.nid+"_connectivity")==="on"?0:1;
    case "power": return st("switch."+p.topic)==="on"?0:1;
    case "load": return num(st("sensor."+p.topic+"_energy_power"))||0;
    case "r5": return w.r5||0; case "r1": return w.r1||0; case "r24": return w.r24||0;
    case "e1": return w.e1||0; case "e24": return w.e24||0;
    case "today": return num(st("sensor."+p.topic+"_energy_today"))||0;
    default: return p.machine;
  }
}
function setSort(col){ if(sortState.col===col) sortState.dir*=-1; else sortState={col:col,dir:1}; scheduleRender(); }

// ---- render ----
function makeHeader(){
  var thead = document.createElement("thead");
  var hdrs = [["Plug","plug",0],["IP","ip",0],["Online","online",0],["Power","power",0],["Controls",null,0],["Load","load",1]];
  var r1 = document.createElement("tr");
  hdrs.forEach(function(h){
    var th=document.createElement("th"); th.rowSpan=2; if(h[2]) th.className="n";
    th.textContent=h[0]; if(sortState.col===h[1]) th.classList.add("sort-active");
    if(h[1]) th.addEventListener("click",(function(c){return function(){setSort(c);};})(h[1]));
    r1.appendChild(th);
  });
  ["Rate","Energy"].forEach(function(g){ var th=document.createElement("th"); th.colSpan=3; th.className="grphdr"; th.textContent=g; r1.appendChild(th); });
  thead.appendChild(r1);
  var r2 = document.createElement("tr");
  [["5m","r5",1],["1h","r1",0],["24h","r24",0],["1h","e1",1],["24h","e24",0],["today","today",0]].forEach(function(s){
    var th=document.createElement("th"); th.className="n"+(s[2]?" grp":""); th.textContent=s[0];
    if(sortState.col===s[1]) th.classList.add("sort-active");
    th.addEventListener("click",(function(c){return function(){setSort(c);};})(s[1]));
    r2.appendChild(th);
  });
  thead.appendChild(r2); return thead;
}
function cellN(html, grp){ var td=document.createElement("td"); td.className="n"+(grp?" grp":""); td.innerHTML=html; return td; }
function plugRow(p){
  var tr = document.createElement("tr");
  var online = st("binary_sensor.gdoc2netcfg_"+p.nid+"_connectivity");
  var relay = st("switch."+p.topic);
  var isOnline = online === "on";
  if(!isOnline) tr.className = "off";
  var ipv4 = st("sensor.gdoc2netcfg_"+p.nid+"_default_ipv4") || p.ipv4;
  var w = win[p.topic] || {};
  var load = num(st("sensor."+p.topic+"_energy_power"));
  var today = num(st("sensor."+p.topic+"_energy_today"));

  var tdPlug=document.createElement("td"); var aP=document.createElement("a");
  aP.href="http://ipv4."+p.fqdn; aP.textContent=p.machine; tdPlug.appendChild(aP); tr.appendChild(tdPlug);

  var tdIp=document.createElement("td");
  if(ipv4){ var aI=document.createElement("a"); aI.href="http://"+ipv4; aI.textContent=ipv4; tdIp.appendChild(aI); }
  tr.appendChild(tdIp);

  var tdOn=document.createElement("td");
  if(isOnline){ tdOn.innerHTML = '<span class="on">'+GREEN+' online</span>'; }
  else {
    var s = seen[p.nid];
    var sx = (st("binary_sensor.gdoc2netcfg_"+p.nid+"_connectivity")===undefined) ? "unknown" : (s || "…");
    tdOn.innerHTML = '<span class="red">'+RED+' offline</span><div class="seen">last seen '+sx+'</div>';
  }
  tr.appendChild(tdOn);

  var tdPw=document.createElement("td"); var tg=document.createElement("span"); tg.className="toggle";
  if(relay==="on"){ tg.classList.add("on"); tg.textContent=GREEN+" ON"; }
  else if(relay==="off"){ tg.classList.add("offdot"); tg.textContent=WHITE+" OFF"; }
  else { tg.classList.add("offdot"); tg.textContent="—"; }
  if(relay==="on"||relay==="off") tg.addEventListener("click",(function(pp){return function(){
    var what = pp.controls.length ? " (controls: "+pp.controls.join(", ")+")" : "";
    if(confirm("Toggle "+pp.machine+what+"?")) send({type:"call_service",domain:"switch",service:"toggle",target:{entity_id:"switch."+pp.topic}});
  };})(p));
  tdPw.appendChild(tg); tr.appendChild(tdPw);

  tr.appendChild(controlsCell(p, relay));

  var tdLoad = cellN(fmtW(load)); tdLoad.classList.add("load"); tr.appendChild(tdLoad);
  tr.appendChild(cellN(fmtW(w.r5), true));
  tr.appendChild(cellN(fmtW(w.r1)));
  tr.appendChild(cellN(fmtW(w.r24)));
  tr.appendChild(cellN(fmtKwh(w.e1), true));
  tr.appendChild(cellN(fmtKwh(w.e24)));
  tr.appendChild(cellN(fmtKwh(today)));
  return tr;
}
function render(){
  var root = document.getElementById("dashboard");
  while(root.firstChild) root.removeChild(root.firstChild);

  var h2e = document.createElement("h2"); h2e.textContent = "Examples — all states (illustrative, not real devices)"; root.appendChild(h2e);
  root.appendChild(exampleTable());

  var h2f = document.createElement("h2"); h2f.textContent = "Welland fleet"; root.appendChild(h2f);
  var table = document.createElement("table");
  table.appendChild(makeHeader());
  var tbody = document.createElement("tbody");
  var sorted = PLUGS.slice().sort(function(a,b){
    var va=sortVal(a,sortState.col), vb=sortVal(b,sortState.col);
    var c = (typeof va==="number"&&typeof vb==="number") ? va-vb : natCmp(va,vb);
    return c!==0 ? c*sortState.dir : natCmp(a.machine,b.machine);
  });
  var totLoad=0, totE24=0, nOnline=0, nOn=0;
  sorted.forEach(function(p){
    tbody.appendChild(plugRow(p));
    if(st("binary_sensor.gdoc2netcfg_"+p.nid+"_connectivity")==="on") nOnline++;
    if(st("switch."+p.topic)==="on"){ nOn++; var l=num(st("sensor."+p.topic+"_energy_power")); if(typeof l==="number") totLoad+=l; }
    var e=(win[p.topic]||{}).e24; if(typeof e==="number") totE24+=e;
  });
  table.appendChild(tbody);
  var tfoot=document.createElement("tfoot"); var ftr=document.createElement("tr");
  var f1=document.createElement("td"); f1.colSpan=5; f1.textContent=PLUGS.length+" plugs · "+nOnline+" online · "+nOn+" relay ON"; ftr.appendChild(f1);
  ftr.appendChild(cellN('<span class="load">'+totLoad.toFixed(0)+'&nbsp;W</span>'));
  ftr.appendChild(cellN("", true)); ftr.appendChild(cellN("")); ftr.appendChild(cellN(""));
  ftr.appendChild(cellN("", true)); ftr.appendChild(cellN(totE24.toFixed(3)+"&nbsp;kWh")); ftr.appendChild(cellN(""));
  tfoot.appendChild(ftr); table.appendChild(tfoot);
  root.appendChild(table);
}

// ---- static examples legend ----
function exampleTable(){
  var html = ''
   + '<table>' + makeHeaderHTML()
   + '<tbody>'
   + exRow("online · on · drawing", onCell(true), pw("on"), ctrlDev(GREEN,"server-a"), 42,40,41,39,0.041,0.98,0.30)
   + exRow("relay off (standby)", onCell(true), pw("off"), ctrlDev(WHITE,"server-d","dim"), 0,0,0,0,0,0,0)
   + exRow(WARN+" device on, plug off", onCell(true), pw("off"), ctrlDev(WARN,"server-b"), 0,0,0,0,0,0,0)
   + exRow(RED+" device off, plug on", onCell(true), pw("on"), ctrlDev(RED,"server-c"), 6,5,6,6,0.006,0.14,0.05)
   + exRow(BANG+" unlisted load", onCell(true), pw("on"), '<td class="ctrl"><span class="warn">'+BANG+' unlisted load</span></td>', 30,29,30,28,0.030,0.70,0.22)
   + exRow("other controls", onCell(true), pw("on"), '<td class="ctrl"><div><span class="offdot">• unknown-host</span></div><div><span class="offdot">• Some Free Text</span></div></td>', 12,11,12,12,0.012,0.28,0.09)
   + exRow("plug offline (recent)", onCell(false,"5 minutes ago"), pw(""), ctrlDev(WHITE,"server-e","dim"), null,null,null,null,null,null,null)
   + exRow("plug offline (&gt;14d)", onCell(false,">14 days ago"), pw(""), '<td class="ctrl"><span class="offdot">—</span></td>', null,null,null,null,null,null,null)
   + exRow("plug offline (no history)", onCell(false,"unknown"), pw(""), '<td class="ctrl"><span class="offdot">—</span></td>', null,null,null,null,null,null,null)
   + '</tbody></table>';
  var d = document.createElement("div"); d.innerHTML = html; return d.firstChild;
}
function makeHeaderHTML(){
  return '<thead><tr>'
    + '<th rowspan="2">Plug</th><th rowspan="2">IP</th><th rowspan="2">Online</th>'
    + '<th rowspan="2">Power</th><th rowspan="2">Controls</th><th rowspan="2" class="n">Load</th>'
    + '<th colspan="3" class="grphdr">Rate</th><th colspan="3" class="grphdr">Energy</th></tr>'
    + '<tr><th class="n grp">5m</th><th class="n">1h</th><th class="n">24h</th>'
    + '<th class="n grp">1h</th><th class="n">24h</th><th class="n">today</th></tr></thead>';
}
function onCell(isOnline, seenTxt){
  return isOnline ? '<span class="on">'+GREEN+' online</span>'
    : '<span class="red">'+RED+' offline</span><div class="seen">last seen '+seenTxt+'</div>';
}
function pw(state){
  if(state==="on") return '<span class="toggle on">'+GREEN+' ON</span>';
  if(state==="off") return '<span class="toggle offdot">'+WHITE+' OFF</span>';
  return '<span class="toggle offdot">—</span>';
}
function ctrlDev(icon,name,cls){ return '<td class="ctrl"><div'+(cls?' class="'+cls+'"':'')+'>'+icon+' <a href="#">'+name+'</a></div></td>'; }
function exRow(label, online, power, controlsTd, load,r5,r1,r24,e1,e24,today){
  return '<tr><td><b>'+label+'</b></td><td><span class="offdot">—</span></td>'
    + '<td>'+online+'</td><td>'+power+'</td>'+controlsTd
    + '<td class="n load">'+fmtW(load)+'</td>'
    + '<td class="n grp">'+fmtW(r5)+'</td><td class="n">'+fmtW(r1)+'</td><td class="n">'+fmtW(r24)+'</td>'
    + '<td class="n grp">'+fmtKwh(e1)+'</td><td class="n">'+fmtKwh(e24)+'</td><td class="n">'+fmtKwh(today)+'</td></tr>';
}

render();
haConnect();
</script>
</body>
</html>
```

- [ ] **Step 2: Sanity-check the template has the placeholders the generator will replace**

Run: `grep -o '__[A-Z_]*__' scripts/ha-plug-dashboard.html | sort -u`
Expected: `__DOMAIN__`, `__HA_TOKEN__`, `__HA_WS_URL__`, `__PLUGS_JSON__`.

- [ ] **Step 3: Commit**

```bash
git add scripts/ha-plug-dashboard.html
git commit -m "feat(plugs): Power Plugs dashboard HTML/JS template"
```

---

### Task 4: Generator wiring + standalone dashboard + live verification

**Files:**
- Modify: `scripts/ha-create-reachability-dashboard.py`

**Interfaces:**
- Consumes: `_select_plug_hosts`, `_build_plug_data`, `_verify_plug_entities` (Tasks 1–2); existing `_load_pipeline`, `_fetch_ha_states`, `_deploy_html`, `_js_esc`, `recv_result` pattern, and `config` (with `config.site.domain`, `config.homeassistant.token`, `config.homeassistant.url`).
- Produces: `_generate_plug_html(plugs_data, domain, config) -> str`, `_ensure_plug_dashboard(config)` (async), constants `HA_PLUG_WWW_PATH`, `HA_PLUG_PANEL_URL`; `main()` generates + deploys the plug dashboard.

- [ ] **Step 1: Add constants**

In `scripts/ha-create-reachability-dashboard.py`, next to the existing `HA_SWITCH_WWW_PATH` constants, add:

```python
HA_PLUG_WWW_PATH = "/config/www/network-power-plugs.html"
HA_PLUG_PANEL_URL = "/local/network-power-plugs.html"
```

- [ ] **Step 2: Add the template path + HTML generator**

After `_SWITCH_HTML_TEMPLATE_PATH = ...`, add:

```python
_PLUG_HTML_TEMPLATE_PATH = Path(__file__).parent / "ha-plug-dashboard.html"


def _generate_plug_html(plugs_data: list[dict], domain: str, config) -> str:
    """Bake plug structural JSON into the plug dashboard template."""
    data_json = json.dumps(plugs_data, separators=(",", ":")).replace("</", r"<\/")
    ws_url = f"wss://ha.{domain}/api/websocket"
    template = _PLUG_HTML_TEMPLATE_PATH.read_text()
    return (
        template
        .replace("__PLUGS_JSON__", data_json)
        .replace("__DOMAIN__", _js_esc(domain))
        .replace("__HA_WS_URL__", _js_esc(ws_url))
        .replace("__HA_TOKEN__", _js_esc(config.homeassistant.token))
    )
```

- [ ] **Step 3: Add the standalone-dashboard creator**

After `_ensure_iframe_dashboard`, add `_ensure_plug_dashboard` (same auth + `recv_result` pattern; one panel view):

```python
async def _ensure_plug_dashboard(config) -> None:
    """Create or update the standalone 'Power Plugs' Lovelace dashboard."""
    import time

    import websockets

    ws_url = (
        config.homeassistant.url.rstrip("/")
        .replace("http://", "ws://").replace("https://", "wss://")
        + "/api/websocket"
    )
    async with websockets.connect(ws_url, max_size=10 * 1024 * 1024) as ws:
        async def recv_result(expected_id: int, timeout: float = 30.0) -> dict:
            deadline = asyncio.get_event_loop().time() + timeout
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    raise TimeoutError(f"No WS response for id={expected_id}")
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=remaining))
                if msg.get("id") == expected_id:
                    return msg

        await ws.recv()  # auth_required
        await ws.send(json.dumps({"type": "auth", "access_token": config.homeassistant.token}))
        if json.loads(await ws.recv()).get("type") != "auth_ok":
            raise RuntimeError("Auth failed")

        msg_id = 1
        await ws.send(json.dumps({"id": msg_id, "type": "lovelace/dashboards/list"}))
        resp = await recv_result(msg_id); msg_id += 1
        if not resp.get("success"):
            raise RuntimeError(f"Failed to list dashboards: {resp.get('error')}")
        exists = any(d.get("url_path") == "power-plugs" for d in resp["result"])

        if not exists:
            await ws.send(json.dumps({
                "id": msg_id, "type": "lovelace/dashboards/create",
                "url_path": "power-plugs", "title": "Power Plugs",
                "icon": "mdi:power-plug", "require_admin": False, "show_in_sidebar": True,
            }))
            resp = await recv_result(msg_id); msg_id += 1
            if not resp.get("success"):
                raise RuntimeError(f"Failed to create dashboard: {resp.get('error')}")
            print("Created dashboard 'power-plugs'")

        bust = int(time.time())
        await ws.send(json.dumps({
            "id": msg_id, "type": "lovelace/config/save", "url_path": "power-plugs",
            "config": {"views": [{
                "title": "Power Plugs", "path": "default", "icon": "mdi:power-plug",
                "panel": True,
                "cards": [{"type": "iframe", "url": f"{HA_PLUG_PANEL_URL}?v={bust}", "aspect_ratio": ""}],
            }]},
        }))
        resp = await recv_result(msg_id); msg_id += 1
        if not resp.get("success"):
            raise RuntimeError(f"Failed to save dashboard config: {resp.get('error')}")
        print("Power Plugs dashboard config saved")
```

- [ ] **Step 4: Wire into `main()`**

In `main()`, after the switch dashboard block (`_deploy_html(switch_html, HA_SWITCH_WWW_PATH)` and before `asyncio.run(_ensure_iframe_dashboard(config))`), add:

```python
    print("Generating Power Plugs dashboard...")
    plug_hosts = _select_plug_hosts(hosts)
    plugs_data = [_build_plug_data(h, domain) for h in plug_hosts]
    _verify_plug_entities(plugs_data, ha_states)
    plug_html = _generate_plug_html(plugs_data, domain, config)
    print(f"  {len(plugs_data)} plugs, {len(plug_html):,} bytes")
    _deploy_html(plug_html, HA_PLUG_WWW_PATH)
```

Then after `asyncio.run(_ensure_iframe_dashboard(config))`, add:

```python
    asyncio.run(_ensure_plug_dashboard(config))
```

And add to the final "Dashboards at:" print block:

```python
    print(f"  https://ha.{domain}/power-plugs/default")
```

- [ ] **Step 5: Lint + run the full generator (deploys live)**

Run: `uv run ruff check scripts/`
Expected: no errors.

Run: `uv run scripts/ha-create-reachability-dashboard.py`
Expected output includes `Generating Power Plugs dashboard...`, a plug count (~53), `Deployed to ha...network-power-plugs.html`, `Power Plugs dashboard config saved`, and the final `https://ha.welland.mithis.com/power-plugs/default` line. Any `warning: plug ... missing HA entities` lines indicate data issues to note (should be none on a healthy fleet).

- [ ] **Step 6: Verify live in a browser**

Open `https://ha.welland.mithis.com/power-plugs/default`. Confirm against the committed mockup PNG:
- Status bar reaches "Live — N plugs".
- Online (🟢/🔴 + relative last-seen on offline rows), Power toggle constant size, Load/Rate/Energy populate with units; zeros greyed; energy decimals aligned.
- Controls list shows per-device 🟢/⚪(dim)/🔴/⚠️ icons + links; ❗ unlisted load on au-plug-7/8/10/47.
- Click a column header → re-sorts. Click a Power toggle → confirm dialog naming the plug + controls; on confirm the relay flips (test on a safe plug, e.g. a spare/OFF one — NOT a router/switch/UPS).
- The "Examples" legend table renders all states.

- [ ] **Step 7: Commit**

```bash
git add scripts/ha-create-reachability-dashboard.py
git commit -m "feat(plugs): generate + deploy the standalone Power Plugs dashboard"
```

---

## Self-review

**Spec coverage:** identity/online/IP (T1 data + T4 render) · relay toggle with confirm (T3/T4) · live load (T3) · energy windows via Σchange statistics (T3) · relative last-seen from history (T3) · relay-aware controls list with icons + ❗ unlisted-load (T3) · grouped columns/aligned decimals/greyed zeros/constant toggle/vertical centering (T3 CSS, matches mockup) · entity verification fail-loud (T2) · standalone dashboard (T4) · examples legend (T3). All covered.

**Placeholders:** none — every step has concrete code/commands.

**Type consistency:** plug dict keys `machine/topic/nid/fqdn/ipv4/controls` are produced in T1 and consumed identically in T2 (`topic`,`machine`) and the T3 template JS (`PLUGS[].topic/nid/fqdn/ipv4/machine/controls`) and T4 (`_build_plug_data`→`_generate_plug_html`). Entity-id forms (`switch.{topic}`, `sensor.{topic}_energy_*`, `binary_sensor.gdoc2netcfg_{nid}_connectivity`, `sensor.gdoc2netcfg_{nid}_default_ipv4`, `sensor.gdoc2netcfg_host_directory`) are consistent across T2/T3/T4.

**Note for executor:** the template JS (T3) is large and verified live (T4 Step 6), not by pytest — expect a fix-iterate loop against real HA (the existing dashboards needed the same). The mockup PNG is the acceptance reference.
