from gdoc2netcfg.sources.zigbee_controls import parse_zigbee_controls

# Real Zigbee Info column order (A..K) plus a user-added Controls column.
_COLS = [
    "Site", "Type", "Entity Name", "Description", "Friendly Name", "State",
    "", "Model", "IEEE Address", "Power Source", "Connected Via",
]
_HEADER = ",".join([*_COLS, "Controls"])
_HEADER_NO_CONTROLS = ",".join(_COLS)


def _row(site, entity, controls):
    cells = [site, "Plug", entity, "", "P", "Online", "", "TS011F",
             "0x00", "Mains", "Router", controls]
    return ",".join(cells)


def test_parse_zigbee_controls_basic():
    csv_text = "\n".join([_HEADER, _row("welland", "Z5", "desktop")])
    recs = parse_zigbee_controls(csv_text)
    assert len(recs) == 1
    r = recs[0]
    assert r.sheet_name == "zigbee"
    assert r.machine == "Z5"
    assert r.site == "welland"
    assert r.extra["Controls"] == "desktop"


def test_parse_zigbee_controls_absent_column_is_silent():
    # Header WITHOUT a Controls column -> no edges, no error.
    csv_text = "\n".join([_HEADER_NO_CONTROLS, ",".join(["welland", "Plug", "Z5"])])
    assert parse_zigbee_controls(csv_text) == []


def test_parse_zigbee_controls_skips_empty_controls():
    csv_text = "\n".join([
        _HEADER,
        _row("welland", "Z5", "desktop"),
        _row("welland", "Z6", ""),   # no Controls value
    ])
    recs = parse_zigbee_controls(csv_text)
    assert [r.machine for r in recs] == ["Z5"]


def test_parse_zigbee_controls_tolerates_stray_first_row():
    csv_text = "\n".join([
        "Zigbee Devices (do not edit by hand)",   # stray banner row
        _HEADER,
        _row("monarto", "Z9", "openmesh-96-00"),
    ])
    recs = parse_zigbee_controls(csv_text)
    assert len(recs) == 1
    assert recs[0].machine == "Z9"
    assert recs[0].site == "monarto"
