"""Discovery database for supplement scan results with historical retention.

Stores results from network scanning supplements (reachability, SSH keys,
SSL certs, SNMP, bridge, NSDP, BMC firmware, tasmota).  All data is
delta-based: a new row is inserted only when the data for a given host
differs from the latest stored row.

Structured tables are used for data types with simple schemas where
per-column queries are valuable (reachability, SSH keys, SSL certs,
BMC firmware).  JSON-blob tables are used for deeply nested data
(SNMP, bridge, NSDP, tasmota).
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

_SNMP_DATA_SQL = """\
CREATE TABLE IF NOT EXISTS snmp_data (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id),
    hostname  TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snmp_scan ON snmp_data(scan_id);
CREATE INDEX IF NOT EXISTS idx_snmp_host ON snmp_data(hostname);
"""

_BRIDGE_DATA_SQL = """\
CREATE TABLE IF NOT EXISTS bridge_data (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id),
    hostname  TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bridge_scan ON bridge_data(scan_id);
CREATE INDEX IF NOT EXISTS idx_bridge_host ON bridge_data(hostname);
"""

_NSDP_DATA_SQL = """\
CREATE TABLE IF NOT EXISTS nsdp_data (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id),
    hostname  TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nsdp_scan ON nsdp_data(scan_id);
CREATE INDEX IF NOT EXISTS idx_nsdp_host ON nsdp_data(hostname);
"""

_TASMOTA_DATA_SQL = """\
CREATE TABLE IF NOT EXISTS tasmota_data (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id),
    hostname  TEXT NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasmota_scan ON tasmota_data(scan_id);
CREATE INDEX IF NOT EXISTS idx_tasmota_host ON tasmota_data(hostname);
"""


class DiscoveryDB(BaseDatabase):
    """SQLite storage for supplement scan results."""

    # v2: reachability.is_tombstone — records "host removed from the
    # inventory" as an INSERT-only delta (see tombstone_missing_reachability).
    SCHEMA_VERSION = 2
    SCHEMA_UPGRADES = {
        2: [
            "ALTER TABLE reachability "
            "ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0",
        ],
    }

    def _create_tables(self, conn: sqlite3.Connection) -> None:
        for stmt in (
            _REACHABILITY_SQL
            + _SSH_HOST_KEYS_SQL
            + _SSL_CERTS_SQL
            + _BMC_FIRMWARE_SQL
            + _SNMP_DATA_SQL
            + _BRIDGE_DATA_SQL
            + _NSDP_DATA_SQL
            + _TASMOTA_DATA_SQL
        ).split(";"):
            stmt = stmt.strip()
            if stmt:
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
    # JSON-blob supplements (SNMP, bridge, NSDP, tasmota)
    # ==================================================================

    def _save_json_blob(
        self,
        table: str,
        scan_id: int,
        data: dict[str, dict],
    ) -> int:
        """Generic delta-based save for JSON-blob supplement tables.

        Compares canonical JSON (``json.dumps(sort_keys=True)``) per host.
        """
        latest = self._latest_json_blobs(table)
        changed = 0
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN")
            for hostname, host_data in data.items():
                canonical = json.dumps(host_data, sort_keys=True)
                if hostname in latest and latest[hostname] == canonical:
                    continue
                changed += 1
                cur.execute(
                    f"INSERT INTO {table} "  # noqa: S608
                    "(scan_id, hostname, data_json) VALUES (?, ?, ?)",
                    (scan_id, hostname, canonical),
                )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return changed

    def _load_latest_json_blob(
        self,
        table: str,
        scan_type: str,
    ) -> dict[str, dict] | None:
        """Generic load for JSON-blob supplement tables."""
        if self.latest_scan_id(scan_type) is None:
            return None
        cur = self._conn.execute(
            f"SELECT d.hostname, d.data_json "  # noqa: S608
            f"FROM {table} d "
            f"WHERE d.scan_id = ("
            f"  SELECT d2.scan_id FROM {table} d2 "
            f"  JOIN scans s ON d2.scan_id = s.id "
            f"  WHERE s.finished_at IS NOT NULL "
            f"  AND d2.hostname = d.hostname "
            f"  ORDER BY s.id DESC LIMIT 1"
            f") ORDER BY d.hostname",
        )
        return {
            hostname: json.loads(data_json)
            for hostname, data_json in cur.fetchall()
        }

    def _latest_json_blobs(
        self,
        table: str,
    ) -> dict[str, str]:
        """Build hostname -> canonical JSON string for comparison."""
        cur = self._conn.execute(
            f"SELECT d.hostname, d.data_json "  # noqa: S608
            f"FROM {table} d "
            f"WHERE d.scan_id = ("
            f"  SELECT d2.scan_id FROM {table} d2 "
            f"  JOIN scans s ON d2.scan_id = s.id "
            f"  WHERE s.finished_at IS NOT NULL "
            f"  AND d2.hostname = d.hostname "
            f"  ORDER BY s.id DESC LIMIT 1"
            f")",
        )
        return {hostname: data_json for hostname, data_json in cur.fetchall()}

    # -- SNMP --

    def save_snmp(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_json_blob("snmp_data", scan_id, data)

    def load_latest_snmp(self) -> dict[str, dict] | None:
        return self._load_latest_json_blob("snmp_data", "snmp")

    # -- Bridge --

    def save_bridge(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_json_blob("bridge_data", scan_id, data)

    def load_latest_bridge(self) -> dict[str, dict] | None:
        return self._load_latest_json_blob("bridge_data", "bridge")

    # -- NSDP --

    def save_nsdp(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_json_blob("nsdp_data", scan_id, data)

    def load_latest_nsdp(self) -> dict[str, dict] | None:
        return self._load_latest_json_blob("nsdp_data", "nsdp")

    # -- Tasmota --

    def save_tasmota(self, scan_id: int, data: dict[str, dict]) -> int:
        return self._save_json_blob("tasmota_data", scan_id, data)

    def load_latest_tasmota(self) -> dict[str, dict] | None:
        return self._load_latest_json_blob("tasmota_data", "tasmota")

    # ==================================================================
    # History / time-travel queries
    # ==================================================================

    # Valid table names for host_changes() — prevents SQL injection.
    _HISTORY_TABLES = frozenset({
        "snmp_data", "bridge_data", "nsdp_data", "tasmota_data",
    })

    def host_changes(
        self,
        table: str,
        hostname: str,
        *,
        scan_type: str,
        since: str | None = None,
    ) -> list[tuple[str, dict]]:
        """Return (timestamp, data_dict) for every change to a host.

        Works for JSON-blob tables.  Every row IS a change, newest first.
        """
        if table not in self._HISTORY_TABLES:
            raise ValueError(
                f"Invalid table {table!r}; must be one of {sorted(self._HISTORY_TABLES)}"
            )
        clauses = [
            "d.hostname = ?",
            "s.finished_at IS NOT NULL",
            "s.scan_type = ?",
        ]
        params: list[str] = [hostname, scan_type]
        if since is not None:
            clauses.append("s.started_at >= ?")
            params.append(since)
        where = " AND ".join(clauses)
        cur = self._conn.execute(
            f"SELECT s.started_at, d.data_json "  # noqa: S608
            f"FROM {table} d "
            f"JOIN scans s ON d.scan_id = s.id "
            f"WHERE {where} ORDER BY s.id DESC",
            params,
        )
        return [
            (ts, json.loads(data_json))
            for ts, data_json in cur.fetchall()
        ]


# -- Helpers ---------------------------------------------------------------

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
