"""Discovery database for supplement scan results with historical retention.

Stores results from network scanning supplements (reachability, SSH keys,
SSL certs, SNMP, bridge, NSDP, BMC firmware, tasmota, zigbee).  Every
supplement is stored in typed, structured tables.  All data is
delta-based: rows are inserted only for an entity (host, switch, device,
site) whose values actually changed since its latest stored state.
"""

from __future__ import annotations

import json
import sqlite3

from gdoc2netcfg.storage.base import BaseDatabase

# -- Table DDL -------------------------------------------------------------

_REACHABILITY_SQL = """\
CREATE TABLE IF NOT EXISTS reachability (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    hostname      TEXT NOT NULL,
    interface_idx INTEGER NOT NULL,
    ip            TEXT NOT NULL,
    is_reachable  INTEGER NOT NULL,
    transmitted   INTEGER NOT NULL,
    received      INTEGER NOT NULL,
    rtt_avg_ms    REAL,
    is_tombstone  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reach_scan ON reachability(scan_id);
CREATE INDEX IF NOT EXISTS idx_reach_host ON reachability(hostname);
"""

_SSH_HOST_KEYS_SQL = """\
CREATE TABLE IF NOT EXISTS ssh_host_keys (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id),
    hostname  TEXT NOT NULL,
    key_type  TEXT NOT NULL,
    key_data  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sshkeys_scan ON ssh_host_keys(scan_id);
CREATE INDEX IF NOT EXISTS idx_sshkeys_host ON ssh_host_keys(hostname);
"""

_SSL_CERTS_SQL = """\
CREATE TABLE IF NOT EXISTS ssl_certs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    hostname    TEXT NOT NULL,
    issuer      TEXT NOT NULL,
    self_signed INTEGER NOT NULL,
    valid       INTEGER NOT NULL,
    expiry      TEXT NOT NULL,
    sans_json   TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_ssl_scan ON ssl_certs(scan_id);
CREATE INDEX IF NOT EXISTS idx_ssl_host ON ssl_certs(hostname);
"""

_BMC_FIRMWARE_SQL = """\
CREATE TABLE IF NOT EXISTS bmc_firmware (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id           INTEGER NOT NULL REFERENCES scans(id),
    hostname          TEXT NOT NULL,
    product_name      TEXT NOT NULL,
    firmware_revision TEXT NOT NULL,
    ipmi_version      TEXT NOT NULL,
    series            INTEGER,
    snmp_capable      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bmc_scan ON bmc_firmware(scan_id);
CREATE INDEX IF NOT EXISTS idx_bmc_host ON bmc_firmware(hostname);
"""

# ==========================================================================
# Structured supplement tables (v4)
# ==========================================================================
#
# Each supplement's per-entity document is exploded into typed tables.
# Delta storage is per ENTITY — the finest unit with a stable key: SNMP
# host, bridge/NSDP switch, tasmota device, zigbee device and per-site
# bridge info.  Only an entity whose values changed gets rows under the
# new scan_id; reads reconstruct each entity from its latest completed
# scan.  The save/load dict shapes are unchanged from the JSON-blob era,
# so scanners and consumers are unaffected.
#
# List-valued fields are described by specs: (doc key, table, columns,
# column types).  The DDL, insertion, validation, and reconstruction are
# all driven from the same spec, so they cannot drift apart.

_BRIDGE_DOC_FIELDS = (
    ("mac_table", "bridge_mac_table",
     ("mac", "vlan_id", "bridge_port", "port_name"), (str, int, int, str)),
    ("vlan_names", "bridge_vlan_names",
     ("vlan_id", "name"), (int, str)),
    ("port_pvids", "bridge_port_pvids",
     ("port", "pvid"), (int, int)),
    ("port_names", "bridge_port_names",
     ("port", "name"), (int, str)),
    ("port_aliases", "bridge_port_aliases",
     ("port", "alias"), (int, str)),
    ("port_status", "bridge_port_status",
     ("port", "oper_status", "speed_mbps"), (int, int, int)),
    ("lldp_neighbors", "bridge_lldp_neighbors",
     ("local_port", "remote_sysname", "remote_port_id", "remote_chassis"),
     (int, str, str, str)),
    ("vlan_egress_ports", "bridge_vlan_egress_ports",
     ("vlan_id", "port_bitmap_hex"), (int, str)),
    ("vlan_untagged_ports", "bridge_vlan_untagged_ports",
     ("vlan_id", "port_bitmap_hex"), (int, str)),
    ("poe_status", "bridge_poe_status",
     ("port", "admin_status", "detection_status"), (int, int, int)),
    # Counters a switch doesn't expose for an interface are None (e.g.
    # M4300 VLAN interfaces report ifInErrors but no HC octets).
    ("port_statistics", "bridge_port_statistics",
     ("port", "bytes_rx", "bytes_tx", "errors"),
     (int, (int, type(None)), (int, type(None)), (int, type(None)))),
)

# NSDP scalar fields: (doc key, column, type).  Every one is optional in
# the document — absent is stored as NULL and omitted on reconstruction.
# The document's "hostname" key is the switch's self-reported name; the
# table's hostname column is the spreadsheet hostname keying the entry.
_NSDP_SCALAR_FIELDS = (
    ("hostname", "device_hostname", str),
    ("ip", "ip", str),
    ("netmask", "netmask", str),
    ("gateway", "gateway", str),
    ("firmware_version", "firmware_version", str),
    ("dhcp_enabled", "dhcp_enabled", bool),
    ("port_count", "port_count", int),
    ("serial_number", "serial_number", str),
    ("vlan_engine", "vlan_engine", int),
    ("qos_engine", "qos_engine", int),
    ("port_mirroring_dest", "port_mirroring_dest", int),
    ("igmp_snooping_enabled", "igmp_snooping_enabled", bool),
    ("broadcast_filtering", "broadcast_filtering", bool),
    ("loop_detection", "loop_detection", bool),
)

_NSDP_LIST_FIELDS = (
    ("port_status", "nsdp_port_status",
     ("port", "speed"), (int, int)),
    ("port_pvids", "nsdp_port_pvids",
     ("port", "vlan_id"), (int, int)),
    ("port_statistics", "nsdp_port_statistics",
     ("port", "bytes_rx", "bytes_tx", "crc_errors"), (int, int, int, int)),
)

# Tasmota device fields: (doc key == column, allowed types).  "module"
# is int from live devices but "" in the builder's default — its column
# is declared without a type (NONE affinity) so both round-trip.
_TASMOTA_FIELDS = (
    ("device_name", str),
    ("friendly_name", str),
    ("hostname", str),
    ("firmware_version", str),
    ("mqtt_host", str),
    ("mqtt_port", int),
    ("mqtt_topic", str),
    ("mqtt_client", str),
    ("mqtt_user", str),
    ("mac", str),
    ("ip", str),
    ("wifi_ssid", str),
    ("wifi_rssi", int),
    ("wifi_signal", int),
    ("uptime", str),
    ("module", (int, str)),
    ("mqtt_count", int),
)

# Fields added to the scanner after rows already existed: optional in
# documents (absent stays absent — baseline documents reconstructed
# from pre-v5 rows lack them), stored as NULL when absent.
_TASMOTA_OPTIONAL_FIELDS = frozenset({"mqtt_count"})

# Zigbee device fields (doc key == column except "site", which equals
# the owning site and is not stored).  None-able fields get NULL columns.
_ZIGBEE_DEVICE_FIELDS = (
    ("ieee_address", str),
    ("friendly_name", str),
    ("object_id", str),
    ("device_type", str),
    ("model_id", str),
    ("manufacturer", str),
    ("model", str),
    ("power_source", str),
    ("software_build_id", str),
    ("date_code", str),
    ("last_seen", (int, type(None))),
    ("link_quality", (int, type(None))),
    ("availability", str),
    ("network_address", (int, type(None))),
)

_ZIGBEE_BRIDGE_FIELDS = (
    ("z2m_version", str),
    ("coordinator_ieee", str),
    ("coordinator_type", str),
    ("channel", int),
    ("pan_id", str),
)


def _sql_type(expected: object) -> str:
    """SQL column definition fragment for a spec type."""
    if expected is str:
        return "TEXT NOT NULL"
    if expected in (int, bool):
        return "INTEGER NOT NULL"
    if isinstance(expected, tuple):
        if type(None) in expected:
            inner = [t for t in expected if t is not type(None)]
            if inner == [int]:
                return "INTEGER"
            if inner == [str]:
                return "TEXT"
        # Mixed concrete types (e.g. int | str): no affinity, so the
        # stored type is preserved exactly.
        return "NOT NULL"
    raise ValueError(f"Unmapped spec type {expected!r}")


def _entity_table_ddl(
    table: str,
    entity_col: str,
    columns: tuple[tuple[str, str], ...],
) -> list[str]:
    """CREATE TABLE + index DDL for a per-entity supplement table."""
    col_defs = "".join(f",\n    {name} {sql}" for name, sql in columns)
    return [
        f"CREATE TABLE IF NOT EXISTS {table} (\n"
        f"    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        f"    scan_id INTEGER NOT NULL REFERENCES scans(id),\n"
        f"    {entity_col} TEXT NOT NULL"
        f"{col_defs}\n)",
        f"CREATE INDEX IF NOT EXISTS idx_{table} "
        f"ON {table}({entity_col}, scan_id)",
    ]


def _structured_ddl_statements() -> list[str]:
    """All v4 structured-table DDL (also used by the v3 -> v4 upgrade)."""
    stmts: list[str] = []

    # SNMP: head row per host + one row per (source, row, OID) value.
    stmts += _entity_table_ddl("snmp_hosts", "hostname", (
        ("snmp_version", "TEXT NOT NULL"),
        ("sys_contact", "TEXT NOT NULL"),
        ("sys_descr", "TEXT NOT NULL"),
        ("sys_location", "TEXT NOT NULL"),
        ("sys_name", "TEXT NOT NULL"),
        ("sys_object_id", "TEXT NOT NULL"),
        ("sys_uptime", "TEXT NOT NULL"),
    ))
    stmts += _entity_table_ddl("snmp_oid_values", "hostname", (
        ("source", "TEXT NOT NULL"),    # 'raw' | 'interface' | 'ip_address'
        ("row_idx", "INTEGER NOT NULL"),
        ("oid", "TEXT NOT NULL"),
        ("value", "TEXT NOT NULL"),
    ))

    # Bridge: head row per switch + one table per BridgeData field.
    # port_statistics and port_aliases were added to the scanner later,
    # so historical documents may lack them — the head row records
    # their presence.
    stmts += _entity_table_ddl("bridge_switches", "hostname", (
        ("has_port_statistics", "INTEGER NOT NULL"),
        ("has_port_aliases", "INTEGER NOT NULL"),
    ))
    for _key, table, cols, types in _BRIDGE_DOC_FIELDS:
        stmts += _entity_table_ddl(table, "hostname", tuple(
            (col, _sql_type(typ)) for col, typ in zip(cols, types)
        ))

    # NSDP: head row per switch + list tables + VLAN membership.
    stmts += _entity_table_ddl("nsdp_switches", "hostname", (
        ("model", "TEXT NOT NULL"),
        ("mac", "TEXT NOT NULL"),
        *((col, _sql_type(typ).replace(" NOT NULL", ""))
          for _key, col, typ in _NSDP_SCALAR_FIELDS),
    ))
    for _key, table, cols, types in _NSDP_LIST_FIELDS:
        stmts += _entity_table_ddl(table, "hostname", tuple(
            (col, _sql_type(typ)) for col, typ in zip(cols, types)
        ))
    # One row per (vlan, member port); tagged marks tagged membership.
    # A VLAN with no members keeps a single NULL-port presence row.
    stmts += _entity_table_ddl("nsdp_vlan_members", "hostname", (
        ("vlan_id", "INTEGER NOT NULL"),
        ("port", "INTEGER"),
        ("tagged", "INTEGER"),
    ))

    # Tasmota: one row per device.  The entity column is device_key —
    # a spreadsheet hostname or an "_unknown/<ip>" marker — distinct
    # from the device's self-reported "hostname" field.
    stmts += _entity_table_ddl("tasmota_devices", "device_key", tuple(
        (key,
         _sql_type(typ).replace(" NOT NULL", "")
         if key in _TASMOTA_OPTIONAL_FIELDS else _sql_type(typ))
        for key, typ in _TASMOTA_FIELDS
    ))

    # Zigbee: per-site bridge-info rows and per-device rows, each
    # delta'd independently — a device row is written only when THAT
    # device's stable fields change, a site row only when the bridge
    # info changes (or the site appears / is tombstoned).
    stmts += _entity_table_ddl("zigbee_sites", "site", (
        ("is_tombstone", "INTEGER NOT NULL DEFAULT 0"),
        ("has_bridge", "INTEGER NOT NULL DEFAULT 0"),
        *((key, _sql_type(typ).replace(" NOT NULL", ""))
          for key, typ in _ZIGBEE_BRIDGE_FIELDS),
    ))
    stmts += _entity_table_ddl("zigbee_devices", "site", (
        *((key, _sql_type(typ)) for key, typ in _ZIGBEE_DEVICE_FIELDS),
        ("is_tombstone", "INTEGER NOT NULL DEFAULT 0"),
    ))

    return stmts


# -- Document validation ----------------------------------------------------
#
# Every save (and the v4 migration) validates documents strictly — an
# unexpected key, arity, or value type means the producer changed shape
# and the schema needs a deliberate update, so fail loud.

def _typecheck(what: str, value: object, expected: object) -> None:
    if expected is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif isinstance(expected, tuple):
        ok = any(
            (isinstance(value, int) and not isinstance(value, bool))
            if t is int else isinstance(value, t)
            for t in expected
        )
    else:
        ok = isinstance(value, expected)  # type: ignore[arg-type]
    if not ok:
        raise ValueError(f"{what}: expected {expected}, got {value!r}")


def _expect_keys(
    what: str,
    doc: dict,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> None:
    if not isinstance(doc, dict):
        raise ValueError(f"{what}: expected a dict, got {doc!r}")
    missing = required - set(doc)
    extra = set(doc) - required - optional
    if missing or extra:
        raise ValueError(
            f"{what}: missing keys {sorted(missing)}, "
            f"unexpected keys {sorted(extra)}"
        )


# -- Row insertion (shared by save_* and the v4 migration) -------------------

def _insert_row(
    cur: sqlite3.Cursor,
    table: str,
    entity_col: str,
    scan_id: int,
    entity: str,
    columns: tuple[str, ...],
    values: tuple,
) -> None:
    col_sql = ", ".join(("scan_id", entity_col, *columns))
    placeholders = ", ".join("?" * (len(columns) + 2))
    cur.execute(
        f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders})",  # noqa: S608
        (scan_id, entity, *values),
    )


def _insert_list_rows(
    cur: sqlite3.Cursor,
    table: str,
    scan_id: int,
    entity: str,
    columns: tuple[str, ...],
    types: tuple,
    entries: list,
) -> None:
    """Insert one row per fixed-arity list entry, validating each."""
    for entry in entries:
        entry = list(entry)
        if len(entry) != len(columns):
            raise ValueError(
                f"{table}[{entity}]: expected {len(columns)} elements, "
                f"got {entry!r}"
            )
        for col, typ, value in zip(columns, types, entry):
            _typecheck(f"{table}[{entity}].{col}", value, typ)
        _insert_row(cur, table, "hostname", scan_id, entity, columns, tuple(entry))


_SNMP_DOC_KEYS = frozenset(
    {"snmp_version", "system_info", "interfaces", "ip_addresses", "raw"}
)
_SNMP_SYSTEM_KEYS = (
    "sysContact", "sysDescr", "sysLocation",
    "sysName", "sysObjectID", "sysUpTime",
)


def _insert_snmp_rows(
    cur: sqlite3.Cursor, scan_id: int, hostname: str, doc: dict,
) -> None:
    what = f"snmp[{hostname}]"
    _expect_keys(what, doc, _SNMP_DOC_KEYS)
    _typecheck(f"{what}.snmp_version", doc["snmp_version"], str)
    sysinfo = doc["system_info"]
    _expect_keys(f"{what}.system_info", sysinfo, frozenset(_SNMP_SYSTEM_KEYS))
    for key in _SNMP_SYSTEM_KEYS:
        _typecheck(f"{what}.system_info.{key}", sysinfo[key], str)
    _insert_row(
        cur, "snmp_hosts", "hostname", scan_id, hostname,
        ("snmp_version", "sys_contact", "sys_descr", "sys_location",
         "sys_name", "sys_object_id", "sys_uptime"),
        (doc["snmp_version"], *(sysinfo[k] for k in _SNMP_SYSTEM_KEYS)),
    )

    def put(source: str, row_idx: int, mapping: dict) -> None:
        if not isinstance(mapping, dict) or not mapping:
            raise ValueError(
                f"{what}.{source}[{row_idx}]: expected a non-empty dict, "
                f"got {mapping!r}"
            )
        for oid, value in mapping.items():
            _typecheck(f"{what}.{source}.{oid}", value, str)
            _insert_row(
                cur, "snmp_oid_values", "hostname", scan_id, hostname,
                ("source", "row_idx", "oid", "value"),
                (source, row_idx, oid, value),
            )

    if doc["raw"]:
        put("raw", 0, doc["raw"])
    for i, row in enumerate(doc["interfaces"]):
        put("interface", i, row)
    for i, row in enumerate(doc["ip_addresses"]):
        put("ip_address", i, row)


# Bridge doc keys that later scanner generations added: optional in the
# document, with presence recorded on the bridge_switches head row.
_BRIDGE_OPTIONAL_KEYS = ("port_statistics", "port_aliases")


def _insert_bridge_rows(
    cur: sqlite3.Cursor, scan_id: int, hostname: str, doc: dict,
) -> None:
    _expect_keys(
        f"bridge[{hostname}]", doc,
        frozenset(
            key for key, _t, _c, _ty in _BRIDGE_DOC_FIELDS
            if key not in _BRIDGE_OPTIONAL_KEYS
        ),
        optional=frozenset(_BRIDGE_OPTIONAL_KEYS),
    )
    _insert_row(
        cur, "bridge_switches", "hostname", scan_id, hostname,
        ("has_port_statistics", "has_port_aliases"),
        (int("port_statistics" in doc), int("port_aliases" in doc)),
    )
    for key, table, cols, types in _BRIDGE_DOC_FIELDS:
        if key not in doc:
            continue
        _insert_list_rows(cur, table, scan_id, hostname, cols, types, doc[key])


def _insert_nsdp_rows(
    cur: sqlite3.Cursor, scan_id: int, hostname: str, doc: dict,
) -> None:
    what = f"nsdp[{hostname}]"
    optional = (
        {key for key, _c, _t in _NSDP_SCALAR_FIELDS}
        | {key for key, _t, _c, _ty in _NSDP_LIST_FIELDS}
        | {"vlan_members"}
    )
    _expect_keys(what, doc, frozenset({"model", "mac"}), frozenset(optional))
    _typecheck(f"{what}.model", doc["model"], str)
    _typecheck(f"{what}.mac", doc["mac"], str)

    scalar_cols, scalar_vals = [], []
    for key, col, typ in _NSDP_SCALAR_FIELDS:
        if key in doc:
            _typecheck(f"{what}.{key}", doc[key], typ)
            scalar_cols.append(col)
            scalar_vals.append(int(doc[key]) if typ is bool else doc[key])
    _insert_row(
        cur, "nsdp_switches", "hostname", scan_id, hostname,
        ("model", "mac", *scalar_cols),
        (doc["model"], doc["mac"], *scalar_vals),
    )

    for key, table, cols, types in _NSDP_LIST_FIELDS:
        if key in doc:
            _insert_list_rows(
                cur, table, scan_id, hostname, cols, types, doc[key],
            )

    for entry in doc.get("vlan_members", []):
        entry = list(entry)
        if len(entry) != 3:
            raise ValueError(f"{what}.vlan_members: bad entry {entry!r}")
        vlan_id, members, tagged = entry[0], list(entry[1]), list(entry[2])
        _typecheck(f"{what}.vlan_members.vlan_id", vlan_id, int)
        for port in (*members, *tagged):
            _typecheck(f"{what}.vlan_members.port", port, int)
        if not set(tagged) <= set(members):
            raise ValueError(
                f"{what}.vlan_members vlan {vlan_id}: tagged ports "
                f"{tagged!r} not a subset of members {members!r}"
            )
        if not members:
            # Presence row so a memberless VLAN survives the round trip.
            _insert_row(
                cur, "nsdp_vlan_members", "hostname", scan_id, hostname,
                ("vlan_id", "port", "tagged"), (vlan_id, None, None),
            )
        for port in members:
            _insert_row(
                cur, "nsdp_vlan_members", "hostname", scan_id, hostname,
                ("vlan_id", "port", "tagged"),
                (vlan_id, port, int(port in set(tagged))),
            )


def _insert_tasmota_rows(
    cur: sqlite3.Cursor, scan_id: int, device_key: str, doc: dict,
) -> None:
    what = f"tasmota[{device_key}]"
    _expect_keys(
        what, doc,
        frozenset(key for key, _t in _TASMOTA_FIELDS)
        - _TASMOTA_OPTIONAL_FIELDS,
        optional=_TASMOTA_OPTIONAL_FIELDS,
    )
    for key, typ in _TASMOTA_FIELDS:
        if key in _TASMOTA_OPTIONAL_FIELDS and key not in doc:
            continue
        _typecheck(f"{what}.{key}", doc[key], typ)
    _insert_row(
        cur, "tasmota_devices", "device_key", scan_id, device_key,
        tuple(key for key, _t in _TASMOTA_FIELDS),
        tuple(doc.get(key) for key, _t in _TASMOTA_FIELDS),
    )


def _insert_zigbee_site_row(
    cur: sqlite3.Cursor, scan_id: int, site: str, bridge: dict | None,
) -> None:
    what = f"zigbee[{site}].bridge"
    bridge_vals: tuple = (None,) * len(_ZIGBEE_BRIDGE_FIELDS)
    if bridge is not None:
        _expect_keys(
            what, bridge,
            frozenset({"site", *(k for k, _t in _ZIGBEE_BRIDGE_FIELDS)}),
        )
        if bridge["site"] != site:
            raise ValueError(f"{what}: site {bridge['site']!r} != {site!r}")
        for key, typ in _ZIGBEE_BRIDGE_FIELDS:
            _typecheck(f"{what}.{key}", bridge[key], typ)
        bridge_vals = tuple(bridge[k] for k, _t in _ZIGBEE_BRIDGE_FIELDS)
    _insert_row(
        cur, "zigbee_sites", "site", scan_id, site,
        ("is_tombstone", "has_bridge",
         *(k for k, _t in _ZIGBEE_BRIDGE_FIELDS)),
        (0, int(bridge is not None), *bridge_vals),
    )


def _insert_zigbee_device_row(
    cur: sqlite3.Cursor, scan_id: int, site: str, ieee: str, device: dict,
) -> None:
    what = f"zigbee[{site}].devices[{ieee}]"
    _expect_keys(
        what, device,
        frozenset({"site", *(k for k, _t in _ZIGBEE_DEVICE_FIELDS)}),
    )
    if device["site"] != site or device["ieee_address"] != ieee:
        raise ValueError(
            f"{what}: key mismatch (site={device['site']!r}, "
            f"ieee={device['ieee_address']!r})"
        )
    for key, typ in _ZIGBEE_DEVICE_FIELDS:
        _typecheck(f"{what}.{key}", device[key], typ)
    _insert_row(
        cur, "zigbee_devices", "site", scan_id, site,
        tuple(k for k, _t in _ZIGBEE_DEVICE_FIELDS),
        tuple(device[k] for k, _t in _ZIGBEE_DEVICE_FIELDS),
    )


def _insert_zigbee_device_tombstone(
    cur: sqlite3.Cursor, scan_id: int, site: str, ieee: str,
) -> None:
    """A device removed from its site's registry: INSERT-only tombstone
    (history is never deleted) that drops it from reads; a later real
    row resurrects it."""
    placeholders = tuple(
        "" if typ is str else None for _key, typ in _ZIGBEE_DEVICE_FIELDS
    )
    values = tuple(
        ieee if key == "ieee_address" else placeholder
        for (key, _t), placeholder in zip(_ZIGBEE_DEVICE_FIELDS, placeholders)
    )
    _insert_row(
        cur, "zigbee_devices", "site", scan_id, site,
        (*(k for k, _t in _ZIGBEE_DEVICE_FIELDS), "is_tombstone"),
        (*values, 1),
    )


def _validate_zigbee_doc(site: str, doc: dict) -> None:
    _expect_keys(f"zigbee[{site}]", doc, frozenset({"bridge", "devices"}))
    if not isinstance(doc["devices"], dict):
        raise ValueError(f"zigbee[{site}].devices: expected a dict")


def _upgrade_v6_port_aliases(conn: sqlite3.Connection) -> None:
    """Schema v6: bridge scans gained per-port ifAlias capture.

    Pre-v6 head rows default has_port_aliases to 0, so their documents
    reconstruct without the key (aliases were never captured).  The new
    table's DDL is derived from _BRIDGE_DOC_FIELDS so it cannot drift
    from what fresh installs create.
    """
    conn.execute(
        "ALTER TABLE bridge_switches ADD COLUMN "
        "has_port_aliases INTEGER NOT NULL DEFAULT 0"
    )
    _key, table, cols, types = next(
        f for f in _BRIDGE_DOC_FIELDS if f[0] == "port_aliases"
    )
    for stmt in _entity_table_ddl(table, "hostname", tuple(
        (col, _sql_type(typ)) for col, typ in zip(cols, types)
    )):
        conn.execute(stmt)


def _upgrade_v7_extended_bridge_data(conn: sqlite3.Connection) -> None:
    """Schema v7: nullable traffic counters.

    bridge_port_statistics is rebuilt because SQLite cannot drop a
    NOT NULL constraint in place; pre-v7 rows keep their values (the
    old scanner fabricated 0 for missing counters — indistinguishable
    from real zeros, so they are carried over as-is).
    """
    conn.execute(
        "ALTER TABLE bridge_port_statistics RENAME TO bridge_port_statistics_v6"
    )
    conn.execute("DROP INDEX idx_bridge_port_statistics")
    _key, table, cols, types = next(
        f for f in _BRIDGE_DOC_FIELDS if f[0] == "port_statistics"
    )
    for stmt in _entity_table_ddl(table, "hostname", tuple(
        (col, _sql_type(typ)) for col, typ in zip(cols, types)
    )):
        conn.execute(stmt)
    conn.execute(
        "INSERT INTO bridge_port_statistics "
        "(id, scan_id, hostname, port, bytes_rx, bytes_tx, errors) "
        "SELECT id, scan_id, hostname, port, bytes_rx, bytes_tx, errors "
        "FROM bridge_port_statistics_v6"
    )
    conn.execute("DROP TABLE bridge_port_statistics_v6")


class DiscoveryDB(BaseDatabase):
    """SQLite storage for supplement scan results."""

    # Version lineage: v2 added reachability.is_tombstone, v3 a zigbee
    # JSON-blob table, v4 replaced ALL JSON-blob tables with the
    # structured tables above (converting blob history in place).  The
    # v1->v4 upgrade steps were removed once every production database
    # reached v4 — older databases fail loud with no upgrade path.
    # v5: tasmota_devices.mqtt_count (MQTT connection diagnostics).
    # v6: bridge port_aliases (ifAlias port descriptions).
    # v7: nullable traffic counters; vendor PoE power, box sensors,
    #     bridge MAC, LLDP port descriptions.
    SCHEMA_VERSION = 7
    SCHEMA_UPGRADES = {
        5: ["ALTER TABLE tasmota_devices ADD COLUMN mqtt_count INTEGER"],
        6: [_upgrade_v6_port_aliases],
        7: [_upgrade_v7_extended_bridge_data],
    }

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        for stmt in (
            _REACHABILITY_SQL
            + _SSH_HOST_KEYS_SQL
            + _SSL_CERTS_SQL
            + _BMC_FIRMWARE_SQL
        ).split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)
        for stmt in _structured_ddl_statements():
            conn.execute(stmt)

    # ==================================================================
    # Reachability
    # ==================================================================

    def save_reachability(
        self,
        scan_id: int,
        data: dict,
    ) -> int:
        """Store reachability data, delta-based on STATUS (not RTT).

        *data* is ``dict[hostname, HostReachability]`` or the equivalent
        serialised form ``dict[hostname, {"interfaces": [[{ip, ...}]]}]``.

        Change detection compares (ip, is_reachable) sets per interface,
        ignoring RTT noise.

        Returns changed_count.
        """
        latest = self._latest_reachability_status()
        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for hostname, hr in data.items():
                interfaces = _extract_interfaces(hr)
                new_status = _reachability_status_key(interfaces)
                if hostname in latest and latest[hostname] == new_status:
                    continue  # status unchanged
                changed += 1
                for iface_idx, pings in enumerate(interfaces):
                    for ip_str, transmitted, received, rtt in pings:
                        cur.execute(
                            "INSERT INTO reachability "
                            "(scan_id, hostname, interface_idx, ip, "
                            "is_reachable, transmitted, received, rtt_avg_ms) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                scan_id, hostname, iface_idx, ip_str,
                                1 if received > 0 else 0,
                                transmitted, received, rtt,
                            ),
                        )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_reachability(self) -> dict | None:
        """Load latest reachability data per host.

        Returns a dict matching the v2 JSON cache format:
        ``{hostname: {"interfaces": [[{ip, transmitted, received, rtt_avg_ms}]]}}``.

        Hosts whose latest record is a tombstone (removed from the
        inventory) are omitted.  Returns None if no completed
        reachability scan exists.
        """
        latest_id = self.latest_scan_id("reachability")
        if latest_id is None:
            return None

        result: dict[str, dict] = {}
        for hostname, rows in self._latest_reachability_rows().items():
            ifaces: list[list[dict]] = []
            for iface_idx, ip, _up, tx, rx, rtt in rows:
                while len(ifaces) <= iface_idx:
                    ifaces.append([])
                ifaces[iface_idx].append({
                    "ip": ip,
                    "transmitted": tx,
                    "received": rx,
                    "rtt_avg_ms": rtt,
                })
            result[hostname] = {"interfaces": ifaces}
        return result

    def _latest_reachability_rows(self) -> dict[str, list[tuple]]:
        """Rows from each host's most recent finished scan, tombstones excluded.

        Each host's latest data may come from a different scan (delta
        storage — a host only gets rows in the scans that changed it).
        Returns hostname -> [(interface_idx, ip, is_reachable, transmitted,
        received, rtt_avg_ms), ...] sorted by interface and IP.  A host
        whose latest record is a tombstone is omitted entirely.
        """
        cur = self._conn.execute(
            "SELECT r.hostname, r.interface_idx, r.ip, r.is_reachable, "
            "r.transmitted, r.received, r.rtt_avg_ms, r.is_tombstone "
            "FROM reachability r "
            "WHERE r.scan_id = ("
            "  SELECT r2.scan_id FROM reachability r2 "
            "  JOIN scans s ON r2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND r2.hostname = r.hostname "
            "  ORDER BY s.id DESC LIMIT 1"
            ") "
            "ORDER BY r.hostname, r.interface_idx, r.ip"
        )
        hosts: dict[str, list[tuple]] = {}
        tombstoned: set[str] = set()
        for hostname, iface_idx, ip, up, tx, rx, rtt, tomb in cur.fetchall():
            if tomb:
                tombstoned.add(hostname)
                continue
            hosts.setdefault(hostname, []).append(
                (iface_idx, ip, bool(up), tx, rx, rtt)
            )
        for hostname in tombstoned:
            hosts.pop(hostname, None)
        return hosts

    def _latest_reachability_status(self) -> dict[str, frozenset]:
        """Build hostname -> frozenset((iface, ip, is_reachable)) for comparison.

        Tombstoned hosts are excluded — so a re-added host compares
        against nothing and its fresh rows are stored (resurrection),
        and tombstone_missing_reachability never re-tombstones.
        """
        return {
            hostname: frozenset(
                (iface_idx, ip, up)
                for iface_idx, ip, up, _tx, _rx, _rtt in rows
            )
            for hostname, rows in self._latest_reachability_rows().items()
        }

    def tombstone_missing_reachability(
        self, scan_id: int, present: set[str],
    ) -> int:
        """Tombstone hosts that vanished from the scanned host set.

        *present* must be the FULL set of hostnames covered by this scan —
        a reachability scan records every inventory host, up or down, so a
        host absent from it has been removed from the inventory.  Each
        missing host gets a single tombstone row under *scan_id*: an
        INSERT-only delta (history is never deleted) that drops the host
        from ``load_latest_reachability()``.  If the host is later
        re-added, fresh rows under a newer scan supersede the tombstone
        automatically.

        Raises ValueError on an empty *present* set — that means the scan
        itself failed, not that every host was removed.

        Returns the number of hosts tombstoned.
        """
        if not present:
            raise ValueError(
                "tombstone_missing_reachability called with an empty "
                "present set — refusing to tombstone every host."
            )
        missing = sorted(set(self._latest_reachability_status()) - set(present))
        if not missing:
            return 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for hostname in missing:
                cur.execute(
                    "INSERT INTO reachability "
                    "(scan_id, hostname, interface_idx, ip, is_reachable, "
                    "transmitted, received, rtt_avg_ms, is_tombstone) "
                    "VALUES (?, ?, 0, '', 0, 0, 0, NULL, 1)",
                    (scan_id, hostname),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return len(missing)

    # ==================================================================
    # SSH host keys
    # ==================================================================

    def save_ssh_host_keys(
        self,
        scan_id: int,
        data: dict[str, list[str]],
    ) -> int:
        """Store SSH host keys, delta-based per hostname.

        *data* maps hostname -> list of key lines
        (``"hostname key_type base64_data"``).

        Returns changed_count.
        """
        latest = self._latest_ssh_keys_by_host()
        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for hostname, key_lines in data.items():
                new_keys = frozenset(
                    _parse_ssh_key_line(line) for line in key_lines
                )
                if hostname in latest and latest[hostname] == new_keys:
                    continue
                changed += 1
                for key_type, key_data in sorted(new_keys):
                    cur.execute(
                        "INSERT INTO ssh_host_keys "
                        "(scan_id, hostname, key_type, key_data) "
                        "VALUES (?, ?, ?, ?)",
                        (scan_id, hostname, key_type, key_data),
                    )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_ssh_host_keys(self) -> dict[str, list[str]] | None:
        """Load latest SSH host keys per host.

        Returns ``dict[hostname, list[key_line]]`` matching the flat-file
        format.  Each key line is ``"hostname key_type base64_data"``.

        Returns None if no completed ssh_host_keys scan exists.
        """
        if self.latest_scan_id("ssh_host_keys") is None:
            return None

        cur = self._conn.execute(
            "SELECT k.hostname, k.key_type, k.key_data "
            "FROM ssh_host_keys k "
            "WHERE k.scan_id = ("
            "  SELECT k2.scan_id FROM ssh_host_keys k2 "
            "  JOIN scans s ON k2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND k2.hostname = k.hostname "
            "  ORDER BY s.id DESC LIMIT 1"
            ") "
            "ORDER BY k.hostname, k.key_type"
        )
        result: dict[str, list[str]] = {}
        for hostname, key_type, key_data in cur.fetchall():
            line = f"{hostname} {key_type} {key_data}"
            result.setdefault(hostname, []).append(line)
        return result

    def _latest_ssh_keys_by_host(self) -> dict[str, frozenset]:
        """Build hostname -> frozenset((key_type, key_data)) for comparison."""
        cur = self._conn.execute(
            "SELECT k.hostname, k.key_type, k.key_data "
            "FROM ssh_host_keys k "
            "WHERE k.scan_id = ("
            "  SELECT k2.scan_id FROM ssh_host_keys k2 "
            "  JOIN scans s ON k2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND k2.hostname = k.hostname "
            "  ORDER BY s.id DESC LIMIT 1"
            ")"
        )
        entries: dict[str, list[tuple[str, str]]] = {}
        for hostname, key_type, key_data in cur.fetchall():
            entries.setdefault(hostname, []).append((key_type, key_data))
        return {
            h: frozenset(keys) for h, keys in entries.items()
        }

    # ==================================================================
    # SSL certificates
    # ==================================================================

    def save_ssl_certs(
        self,
        scan_id: int,
        data: dict[str, dict],
    ) -> int:
        """Store SSL cert data, delta-based per hostname."""
        latest = self._latest_ssl_certs_by_host()
        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for hostname, cert in data.items():
                sans_json = json.dumps(
                    cert.get("sans", []), sort_keys=True,
                )
                new_tuple = (
                    cert["issuer"],
                    bool(cert["self_signed"]),
                    bool(cert["valid"]),
                    cert["expiry"],
                    sans_json,
                )
                if hostname in latest and latest[hostname] == new_tuple:
                    continue
                changed += 1
                cur.execute(
                    "INSERT INTO ssl_certs "
                    "(scan_id, hostname, issuer, self_signed, valid, "
                    "expiry, sans_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id, hostname, new_tuple[0],
                        int(new_tuple[1]), int(new_tuple[2]),
                        new_tuple[3], new_tuple[4],
                    ),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_ssl_certs(self) -> dict[str, dict] | None:
        """Load latest SSL cert data per host."""
        if self.latest_scan_id("ssl_certs") is None:
            return None
        cur = self._conn.execute(
            "SELECT c.hostname, c.issuer, c.self_signed, c.valid, "
            "c.expiry, c.sans_json "
            "FROM ssl_certs c "
            "WHERE c.id = ("
            "  SELECT c2.id FROM ssl_certs c2 "
            "  JOIN scans s ON c2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND c2.hostname = c.hostname "
            "  ORDER BY s.id DESC LIMIT 1"
            ") ORDER BY c.hostname"
        )
        result: dict[str, dict] = {}
        for hostname, issuer, self_signed, valid, expiry, sans_json in cur.fetchall():
            result[hostname] = {
                "issuer": issuer,
                "self_signed": bool(self_signed),
                "valid": bool(valid),
                "expiry": expiry,
                "sans": json.loads(sans_json),
            }
        return result

    def _latest_ssl_certs_by_host(self) -> dict[str, tuple]:
        cur = self._conn.execute(
            "SELECT c.hostname, c.issuer, c.self_signed, c.valid, "
            "c.expiry, c.sans_json "
            "FROM ssl_certs c "
            "WHERE c.id = ("
            "  SELECT c2.id FROM ssl_certs c2 "
            "  JOIN scans s ON c2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND c2.hostname = c.hostname "
            "  ORDER BY s.id DESC LIMIT 1"
            ")"
        )
        return {
            row[0]: (row[1], bool(row[2]), bool(row[3]), row[4], row[5])
            for row in cur.fetchall()
        }

    # ==================================================================
    # BMC firmware
    # ==================================================================

    def save_bmc_firmware(
        self,
        scan_id: int,
        data: dict[str, dict],
    ) -> int:
        """Store BMC firmware data, delta-based per hostname."""
        latest = self._latest_bmc_by_host()
        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for hostname, fw in data.items():
                new_tuple = (
                    fw["product_name"],
                    fw["firmware_revision"],
                    fw["ipmi_version"],
                    fw.get("series"),
                    bool(fw.get("snmp_capable", False)),
                )
                if hostname in latest and latest[hostname] == new_tuple:
                    continue
                changed += 1
                cur.execute(
                    "INSERT INTO bmc_firmware "
                    "(scan_id, hostname, product_name, firmware_revision, "
                    "ipmi_version, series, snmp_capable) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id, hostname, new_tuple[0], new_tuple[1],
                        new_tuple[2], new_tuple[3], int(new_tuple[4]),
                    ),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_bmc_firmware(self) -> dict[str, dict] | None:
        """Load latest BMC firmware data per host."""
        if self.latest_scan_id("bmc_firmware") is None:
            return None
        cur = self._conn.execute(
            "SELECT b.hostname, b.product_name, b.firmware_revision, "
            "b.ipmi_version, b.series, b.snmp_capable "
            "FROM bmc_firmware b "
            "WHERE b.id = ("
            "  SELECT b2.id FROM bmc_firmware b2 "
            "  JOIN scans s ON b2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND b2.hostname = b.hostname "
            "  ORDER BY s.id DESC LIMIT 1"
            ") ORDER BY b.hostname"
        )
        result: dict[str, dict] = {}
        for hostname, product, fw_rev, ipmi_ver, series, snmp in cur.fetchall():
            result[hostname] = {
                "product_name": product,
                "firmware_revision": fw_rev,
                "ipmi_version": ipmi_ver,
                "series": series,
                "snmp_capable": bool(snmp),
            }
        return result

    def _latest_bmc_by_host(self) -> dict[str, tuple]:
        cur = self._conn.execute(
            "SELECT b.hostname, b.product_name, b.firmware_revision, "
            "b.ipmi_version, b.series, b.snmp_capable "
            "FROM bmc_firmware b "
            "WHERE b.id = ("
            "  SELECT b2.id FROM bmc_firmware b2 "
            "  JOIN scans s ON b2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND b2.hostname = b.hostname "
            "  ORDER BY s.id DESC LIMIT 1"
            ")"
        )
        return {
            row[0]: (row[1], row[2], row[3], row[4], bool(row[5]))
            for row in cur.fetchall()
        }

    # ==================================================================
    # Structured supplements (SNMP, bridge, NSDP, tasmota, zigbee)
    # ==================================================================

    def _latest_entity_scans(
        self, table: str, entity_col: str,
    ) -> dict[str, int]:
        """entity -> the latest completed scan_id holding its rows.

        Each entity's latest data may come from a different scan (delta
        storage — an entity only gets rows in the scans that changed it).
        """
        cur = self._conn.execute(
            f"SELECT DISTINCT t.{entity_col}, t.scan_id "  # noqa: S608
            f"FROM {table} t "
            f"WHERE t.scan_id = ("
            f"  SELECT t2.scan_id FROM {table} t2 "
            f"  JOIN scans s ON t2.scan_id = s.id "
            f"  WHERE s.finished_at IS NOT NULL "
            f"  AND t2.{entity_col} = t.{entity_col} "
            f"  ORDER BY s.id DESC LIMIT 1"
            f")",
        )
        return dict(cur.fetchall())

    def _save_entities(
        self,
        scan_id: int,
        data: dict[str, dict],
        latest: dict[str, dict],
        insert_rows,
    ) -> int:
        """Generic per-entity delta save.

        Compares each document against *latest* (canonical JSON); a
        changed or new entity gets its full row-set inserted via
        *insert_rows*.  Returns changed_count.
        """
        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for entity, doc in data.items():
                if entity in latest and (
                    _canonical_json(latest[entity]) == _canonical_json(doc)
                ):
                    continue
                changed += 1
                insert_rows(cur, scan_id, entity, doc)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def _load_list_rows(
        self,
        table: str,
        columns: tuple[str, ...],
        scan_id: int,
        entity: str,
    ) -> list[list]:
        cur = self._conn.execute(
            f"SELECT {', '.join(columns)} FROM {table} "  # noqa: S608
            f"WHERE scan_id = ? AND hostname = ? ORDER BY id",
            (scan_id, entity),
        )
        return [list(row) for row in cur.fetchall()]

    # -- SNMP --

    def save_snmp(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_entities(
            scan_id, data, self._latest_snmp(), _insert_snmp_rows,
        )

    def load_latest_snmp(self) -> dict[str, dict] | None:
        if self.latest_scan_id("snmp") is None:
            return None
        return self._latest_snmp()

    def _latest_snmp(self) -> dict[str, dict]:
        result = {}
        for hostname, scan_id in sorted(
            self._latest_entity_scans("snmp_hosts", "hostname").items()
        ):
            head = self._conn.execute(
                "SELECT snmp_version, sys_contact, sys_descr, sys_location, "
                "sys_name, sys_object_id, sys_uptime FROM snmp_hosts "
                "WHERE scan_id = ? AND hostname = ?",
                (scan_id, hostname),
            ).fetchone()
            raw: dict[str, str] = {}
            interfaces: dict[int, dict[str, str]] = {}
            ip_addresses: dict[int, dict[str, str]] = {}
            for source, row_idx, oid, value in self._conn.execute(
                "SELECT source, row_idx, oid, value FROM snmp_oid_values "
                "WHERE scan_id = ? AND hostname = ? ORDER BY id",
                (scan_id, hostname),
            ):
                if source == "raw":
                    raw[oid] = value
                elif source == "interface":
                    interfaces.setdefault(row_idx, {})[oid] = value
                elif source == "ip_address":
                    ip_addresses.setdefault(row_idx, {})[oid] = value
                else:
                    raise ValueError(
                        f"snmp_oid_values: unknown source {source!r}"
                    )
            result[hostname] = {
                "snmp_version": head[0],
                "system_info": dict(zip(_SNMP_SYSTEM_KEYS, head[1:])),
                "interfaces": [interfaces[i] for i in sorted(interfaces)],
                "ip_addresses": [ip_addresses[i] for i in sorted(ip_addresses)],
                "raw": raw,
            }
        return result

    # -- Bridge --

    def save_bridge(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_entities(
            scan_id, data, self._latest_bridge(), _insert_bridge_rows,
        )

    def load_latest_bridge(self) -> dict[str, dict] | None:
        if self.latest_scan_id("bridge") is None:
            return None
        return self._latest_bridge()

    def _latest_bridge(self) -> dict[str, dict]:
        result = {}
        for hostname, scan_id in sorted(
            self._latest_entity_scans("bridge_switches", "hostname").items()
        ):
            head = self._conn.execute(
                "SELECT has_port_statistics, has_port_aliases "
                "FROM bridge_switches WHERE scan_id = ? AND hostname = ?",
                (scan_id, hostname),
            ).fetchone()
            present = dict(zip(_BRIDGE_OPTIONAL_KEYS, head))
            result[hostname] = {
                key: self._load_list_rows(table, cols, scan_id, hostname)
                for key, table, cols, _types in _BRIDGE_DOC_FIELDS
                if present.get(key, True)
            }
        return result

    # -- NSDP --

    def save_nsdp(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_entities(
            scan_id, data, self._latest_nsdp(), _insert_nsdp_rows,
        )

    def load_latest_nsdp(self) -> dict[str, dict] | None:
        if self.latest_scan_id("nsdp") is None:
            return None
        return self._latest_nsdp()

    def _latest_nsdp(self) -> dict[str, dict]:
        result = {}
        scalar_cols = ", ".join(col for _k, col, _t in _NSDP_SCALAR_FIELDS)
        for hostname, scan_id in sorted(
            self._latest_entity_scans("nsdp_switches", "hostname").items()
        ):
            head = self._conn.execute(
                f"SELECT model, mac, {scalar_cols} FROM nsdp_switches "  # noqa: S608
                "WHERE scan_id = ? AND hostname = ?",
                (scan_id, hostname),
            ).fetchone()
            doc: dict = {"model": head[0], "mac": head[1]}
            for (key, _col, typ), value in zip(_NSDP_SCALAR_FIELDS, head[2:]):
                if value is not None:
                    doc[key] = bool(value) if typ is bool else value
            for key, table, cols, _types in _NSDP_LIST_FIELDS:
                rows = self._load_list_rows(table, cols, scan_id, hostname)
                if rows:
                    doc[key] = rows
            vlans: dict[int, tuple[list[int], list[int]]] = {}
            for vlan_id, port, tagged in self._conn.execute(
                "SELECT vlan_id, port, tagged FROM nsdp_vlan_members "
                "WHERE scan_id = ? AND hostname = ? ORDER BY id",
                (scan_id, hostname),
            ):
                members, tagged_ports = vlans.setdefault(vlan_id, ([], []))
                if port is not None:
                    members.append(port)
                    if tagged:
                        tagged_ports.append(port)
            if vlans:
                doc["vlan_members"] = [
                    [vlan_id, members, tagged_ports]
                    for vlan_id, (members, tagged_ports) in vlans.items()
                ]
            result[hostname] = doc
        return result

    # -- Tasmota --

    def save_tasmota(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_entities(
            scan_id, data, self._latest_tasmota(), _insert_tasmota_rows,
        )

    def load_latest_tasmota(self) -> dict[str, dict] | None:
        if self.latest_scan_id("tasmota") is None:
            return None
        return self._latest_tasmota()

    def _latest_tasmota(self) -> dict[str, dict]:
        field_cols = ", ".join(key for key, _t in _TASMOTA_FIELDS)
        result = {}
        for device_key, scan_id in sorted(
            self._latest_entity_scans("tasmota_devices", "device_key").items()
        ):
            row = self._conn.execute(
                f"SELECT {field_cols} FROM tasmota_devices "  # noqa: S608
                "WHERE scan_id = ? AND device_key = ?",
                (scan_id, device_key),
            ).fetchone()
            result[device_key] = {
                key: value
                for (key, _t), value in zip(_TASMOTA_FIELDS, row)
                if not (key in _TASMOTA_OPTIONAL_FIELDS and value is None)
            }
        return result

    # -- Zigbee --

    def save_zigbee(self, scan_id: int, data: dict[str, dict]) -> int:
        """Store zigbee data with per-DEVICE deltas; sites independent.

        *data* maps site name -> ``{"bridge": bridge-info | None,
        "devices": {ieee: device}}`` — one document per site, mirroring
        the per-site cache files this replaced.  Only updated values
        get new rows: a device row is written when THAT device's stable
        fields change (last_seen/link_quality churn is ignored, like
        reachability's RTT; stored values are as-of the last meaningful
        change), a site row when the bridge info changes.

        Each scanned site's device set is authoritative — a device of
        that site absent from its document has been removed from that
        Z2M instance and is tombstoned.  scan_zigbee carries failed
        sites' baseline documents forward, so a site absent from *data*
        entirely has been removed from the config: it is tombstoned
        along with all its devices.

        Raises ValueError on empty *data* — that means the scan itself
        failed, not that every site was removed.
        """
        if not data:
            raise ValueError(
                "save_zigbee called with an empty present set — "
                "refusing to tombstone every site."
            )
        latest = self._latest_zigbee()
        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for site, doc in data.items():
                _validate_zigbee_doc(site, doc)
                old = latest.get(site)
                if old is None or old["bridge"] != doc["bridge"]:
                    changed += 1
                    _insert_zigbee_site_row(cur, scan_id, site, doc["bridge"])
                old_devices = old["devices"] if old else {}
                for ieee, device in doc["devices"].items():
                    if ieee in old_devices and (
                        _zigbee_device_comparison_key(old_devices[ieee])
                        == _zigbee_device_comparison_key(device)
                    ):
                        continue
                    changed += 1
                    _insert_zigbee_device_row(cur, scan_id, site, ieee, device)
                for ieee in sorted(set(old_devices) - set(doc["devices"])):
                    changed += 1
                    _insert_zigbee_device_tombstone(cur, scan_id, site, ieee)
            for site in sorted(set(latest) - set(data)):
                changed += 1
                _insert_row(
                    cur, "zigbee_sites", "site", scan_id, site,
                    ("is_tombstone",), (1,),
                )
                for ieee in sorted(latest[site]["devices"]):
                    changed += 1
                    _insert_zigbee_device_tombstone(cur, scan_id, site, ieee)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def load_latest_zigbee(self) -> dict[str, dict] | None:
        if self.latest_scan_id("zigbee") is None:
            return None
        return self._latest_zigbee()

    def _latest_zigbee(self) -> dict[str, dict]:
        """Latest site documents, assembled from per-device latest rows.

        A site whose latest site row is a tombstone is omitted entirely;
        a device whose latest row is a tombstone is omitted from its
        site's document.
        """
        bridge_cols = ", ".join(key for key, _t in _ZIGBEE_BRIDGE_FIELDS)
        device_cols = ", ".join(key for key, _t in _ZIGBEE_DEVICE_FIELDS)
        result: dict[str, dict] = {}
        for site, scan_id in sorted(
            self._latest_entity_scans("zigbee_sites", "site").items()
        ):
            head = self._conn.execute(
                f"SELECT is_tombstone, has_bridge, {bridge_cols} "  # noqa: S608
                "FROM zigbee_sites WHERE scan_id = ? AND site = ?",
                (scan_id, site),
            ).fetchone()
            if head[0]:
                continue  # tombstoned: site removed from the config
            bridge = None
            if head[1]:
                bridge = {"site": site}
                bridge.update(
                    zip((k for k, _t in _ZIGBEE_BRIDGE_FIELDS), head[2:])
                )
            result[site] = {"bridge": bridge, "devices": {}}

        # Each device's latest row independently (per-device deltas).
        cur = self._conn.execute(
            f"SELECT d.site, d.is_tombstone, {device_cols} "  # noqa: S608
            "FROM zigbee_devices d "
            "WHERE d.scan_id = ("
            "  SELECT d2.scan_id FROM zigbee_devices d2 "
            "  JOIN scans s ON d2.scan_id = s.id "
            "  WHERE s.finished_at IS NOT NULL "
            "  AND d2.site = d.site AND d2.ieee_address = d.ieee_address "
            "  ORDER BY s.id DESC LIMIT 1"
            ") ORDER BY d.site, d.ieee_address",
        )
        for site, tomb, *values in cur.fetchall():
            if tomb or site not in result:
                continue
            device = {"site": site}
            device.update(zip((k for k, _t in _ZIGBEE_DEVICE_FIELDS), values))
            result[site]["devices"][device["ieee_address"]] = device
        return result


# -- Helpers ---------------------------------------------------------------

def _canonical_json(data: object) -> str:
    """Canonical JSON for change detection.

    Non-dict payloads (e.g. a null tombstone) compare as-is — so a
    tombstoned key never compares equal to real data and resurrection
    inserts a fresh row.
    """
    return json.dumps(data, sort_keys=True)


# Device fields that change on nearly every scan (activity timestamp
# and radio noise) — excluded from zigbee change detection so hourly
# scans don't re-insert unchanged devices.
_ZIGBEE_VOLATILE_FIELDS = frozenset({"last_seen", "link_quality"})


def _zigbee_device_comparison_key(device: dict) -> str:
    """Canonical JSON of a zigbee device, volatile fields removed."""
    return _canonical_json({
        k: v for k, v in device.items() if k not in _ZIGBEE_VOLATILE_FIELDS
    })


def _extract_interfaces(hr: object) -> list[list[tuple]]:
    """Extract interface ping data from a HostReachability or dict.

    Returns list of interfaces, each a list of (ip, tx, rx, rtt) tuples.
    """
    if isinstance(hr, dict):
        # Serialised form: {"interfaces": [[{ip, ...}]]}
        interfaces = []
        for iface_pings in hr.get("interfaces", []):
            pings = []
            for p in iface_pings:
                pings.append((
                    p["ip"],
                    p["transmitted"],
                    p["received"],
                    p.get("rtt_avg_ms"),
                ))
            interfaces.append(pings)
        return interfaces
    # HostReachability dataclass
    interfaces = []
    for ir in hr.interfaces:
        pings = []
        for ip_str, pr in ir.pings:
            pings.append((ip_str, pr.transmitted, pr.received, pr.rtt_avg_ms))
        interfaces.append(pings)
    return interfaces


def _reachability_status_key(
    interfaces: list[list[tuple]],
) -> frozenset:
    """Extract the stable reachability status, ignoring RTT noise.

    Returns frozenset of (interface_idx, ip, is_reachable) tuples.
    """
    entries = set()
    for iface_idx, pings in enumerate(interfaces):
        for ip_str, _tx, rx, _rtt in pings:
            entries.add((iface_idx, ip_str, rx > 0))
    return frozenset(entries)


def _parse_ssh_key_line(line: str) -> tuple[str, str]:
    """Parse "hostname key_type base64_data" into (key_type, key_data)."""
    parts = line.split(None, 2)
    if len(parts) < 3:
        raise ValueError(f"Invalid SSH key line: {line!r}")
    return (parts[1], parts[2])
