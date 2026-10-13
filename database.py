"""
SecureWatch Persistence Layer — SQLite-backed storage for devices,
events, quarantine, blocklist, and reputation.
Replaces in-memory-only dicts that vanished on restart.
"""
import sqlite3
import json
import time
import threading
from contextlib import contextmanager
from config import DB_PATH

_local = threading.local()


def _get_conn():
    """Thread-local SQLite connection (SQLite objects aren't thread-safe)."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
    return _local.conn


@contextmanager
def get_db():
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    """Create tables if they don't exist."""
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id      TEXT PRIMARY KEY,
            device_name    TEXT,
            manufacturer   TEXT DEFAULT 'Unknown',
            device_type    INTEGER DEFAULT 1,
            risk_score     REAL DEFAULT 0,
            status         TEXT DEFAULT 'SAFE',
            rssi           INTEGER,
            reputation     REAL DEFAULT 100,
            fingerprint    TEXT,
            first_seen     REAL,
            last_seen      REAL,
            request_count  INTEGER DEFAULT 0,
            quarantined    INTEGER DEFAULT 0,
            blocked        INTEGER DEFAULT 0,
            name_changes   INTEGER DEFAULT 0,
            trusted        INTEGER DEFAULT 0,
            reasons        TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id   TEXT,
            device_name TEXT,
            event_type  TEXT,
            status      TEXT,
            risk_score  REAL,
            rssi        INTEGER,
            reasons     TEXT,
            timestamp   REAL
        );

        CREATE TABLE IF NOT EXISTS rssi_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            rssi      INTEGER,
            timestamp REAL
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            timestamp REAL
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
        CREATE INDEX IF NOT EXISTS idx_rssi_device ON rssi_history(device_id);
        CREATE INDEX IF NOT EXISTS idx_activity_device ON activity_log(device_id);
        """)
        
        # Migrations: ensure columns exist for older databases
        _migration_columns = [
            ("trusted", "INTEGER DEFAULT 0"),
            ("reasons", "TEXT"),
            ("brand", "TEXT"),
            ("device_type_str", "TEXT"),
            ("mac_type", "TEXT"),
            ("how_identified", "TEXT"),
        ]
        for col_name, col_type in _migration_columns:
            try:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass


# ----------------------------------
# Device CRUD
# ----------------------------------

def upsert_device(device_id, device_name, manufacturer, device_type,
                  risk_score, status, rssi, reputation, fingerprint,
                  quarantined, blocked, name_changes=0, trusted=0, reasons=None,
                  brand=None, device_type_str=None, mac_type=None, how_identified=None):
    now = time.time()
    reasons_json = json.dumps(reasons or []) if reasons is not None else None
    with get_db() as conn:
        existing = conn.execute(
            "SELECT first_seen, trusted FROM devices WHERE device_id = ?",
            (device_id,)
        ).fetchone()
        first_seen = existing["first_seen"] if existing else now
        is_trusted = trusted if trusted else (existing["trusted"] if existing and "trusted" in existing.keys() else 0)
        
        conn.execute("""
            INSERT INTO devices
                (device_id, device_name, manufacturer, device_type,
                 risk_score, status, rssi, reputation, fingerprint,
                 first_seen, last_seen, request_count, quarantined, blocked,
                 name_changes, trusted, reasons, brand, device_type_str, mac_type, how_identified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                device_name   = excluded.device_name,
                manufacturer  = excluded.manufacturer,
                device_type   = excluded.device_type,
                risk_score    = excluded.risk_score,
                status        = excluded.status,
                rssi          = excluded.rssi,
                reputation    = excluded.reputation,
                fingerprint   = excluded.fingerprint,
                last_seen     = excluded.last_seen,
                request_count = request_count + 1,
                quarantined   = excluded.quarantined,
                blocked       = excluded.blocked,
                name_changes  = excluded.name_changes,
                trusted       = CASE WHEN excluded.trusted != 0 THEN excluded.trusted ELSE devices.trusted END,
                reasons       = excluded.reasons,
                brand         = COALESCE(excluded.brand, devices.brand),
                device_type_str = COALESCE(excluded.device_type_str, devices.device_type_str),
                mac_type      = COALESCE(excluded.mac_type, devices.mac_type),
                how_identified = COALESCE(excluded.how_identified, devices.how_identified)
        """, (device_id, device_name, manufacturer, device_type,
              risk_score, status, rssi, reputation, fingerprint,
              first_seen, now, quarantined, blocked, name_changes, is_trusted, reasons_json,
              brand, device_type_str, mac_type, how_identified))


def get_all_devices(limit=500):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?",
            (limit,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["trusted"] = bool(d.get("trusted", 0))
            if d.get("reasons"):
                try:
                    d["reasons"] = json.loads(d["reasons"])
                except Exception:
                    d["reasons"] = []
            else:
                d["reasons"] = []
            result.append(d)
        return result


def get_device(device_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["trusted"] = bool(d.get("trusted", 0))
        if d.get("reasons"):
            try:
                d["reasons"] = json.loads(d["reasons"])
            except Exception:
                d["reasons"] = []
        else:
            d["reasons"] = []
        return d


def set_trusted(device_id: str, trusted: bool, status: str = "SAFE", risk_score: float = 0.0, reputation: float = 100.0, reasons=None):
    reasons_json = json.dumps(reasons or []) if reasons is not None else None
    with get_db() as conn:
        if trusted:
            conn.execute("""
                UPDATE devices 
                SET trusted = 1, status = ?, risk_score = ?, reputation = ?, blocked = 0, quarantined = 0,
                    reasons = COALESCE(?, reasons)
                WHERE device_id = ?
            """, (status, risk_score, reputation, reasons_json, device_id))
        else:
            conn.execute("UPDATE devices SET trusted = 0 WHERE device_id = ?", (device_id,))


def clear_all_data():
    """Reset devices, events, rssi_history, and activity_log tables."""
    with get_db() as conn:
        conn.execute("DELETE FROM devices")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM rssi_history")
        conn.execute("DELETE FROM activity_log")



def set_blocked(device_id, blocked: bool):
    with get_db() as conn:
        conn.execute(
            "UPDATE devices SET blocked = ?, quarantined = ? WHERE device_id = ?",
            (1 if blocked else 0, 1 if blocked else 0, device_id)
        )


def is_blocked(device_id) -> bool:
    with get_db() as conn:
        row = conn.execute(
            "SELECT blocked FROM devices WHERE device_id = ?", (device_id,)
        ).fetchone()
        return bool(row and row["blocked"])


# ----------------------------------
# Events
# ----------------------------------

def add_event(device_id, device_name, event_type, status, risk_score,
              rssi=None, reasons=None):
    ts = time.time()
    with get_db() as conn:
        conn.execute("""
            INSERT INTO events (device_id, device_name, event_type, status,
                                risk_score, rssi, reasons, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (device_id, device_name, event_type, status, risk_score,
              rssi, json.dumps(reasons or []), ts))


def get_events(limit=200, since=None):
    with get_db() as conn:
        if since:
            rows = conn.execute(
                "SELECT * FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (since, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("reasons"):
                try:
                    d["reasons"] = json.loads(d["reasons"])
                except (json.JSONDecodeError, TypeError):
                    pass
            result.append(d)
        return result


# ----------------------------------
# RSSI History
# ----------------------------------

def add_rssi(device_id, rssi):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO rssi_history (device_id, rssi, timestamp) VALUES (?, ?, ?)",
            (device_id, rssi, time.time())
        )
        # Keep only last N per device
        conn.execute("""
            DELETE FROM rssi_history WHERE id NOT IN (
                SELECT id FROM rssi_history WHERE device_id = ?
                ORDER BY timestamp DESC LIMIT 50
            ) AND device_id = ?
        """, (device_id, device_id))


def get_rssi_history(device_id, limit=50):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT rssi, timestamp FROM rssi_history WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?",
            (device_id, limit)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


# ----------------------------------
# Activity tracking
# ----------------------------------

def record_activity(device_id):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO activity_log (device_id, timestamp) VALUES (?, ?)",
            (device_id, time.time())
        )


def get_request_count(device_id, window_seconds=60):
    cutoff = time.time() - window_seconds
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM activity_log WHERE device_id = ? AND timestamp > ?",
            (device_id, cutoff)
        ).fetchone()
        return row["cnt"] if row else 0


def cleanup_old_activity(window_seconds=300):
    """Remove activity records older than window to keep DB small."""
    cutoff = time.time() - window_seconds
    with get_db() as conn:
        conn.execute("DELETE FROM activity_log WHERE timestamp < ?", (cutoff,))


# ----------------------------------
# Stats
# ----------------------------------

def get_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) as c FROM devices").fetchone()["c"]
        safe = conn.execute("SELECT COUNT(*) as c FROM devices WHERE status='SAFE'").fetchone()["c"]
        unverified = conn.execute("SELECT COUNT(*) as c FROM devices WHERE status='UNVERIFIED'").fetchone()["c"]
        suspicious = conn.execute("SELECT COUNT(*) as c FROM devices WHERE status='SUSPICIOUS'").fetchone()["c"]
        attacks = conn.execute("SELECT COUNT(*) as c FROM devices WHERE status='ATTACK'").fetchone()["c"]
        quarantined = conn.execute("SELECT COUNT(*) as c FROM devices WHERE quarantined=1").fetchone()["c"]
        blocked = conn.execute("SELECT COUNT(*) as c FROM devices WHERE blocked=1").fetchone()["c"]
        total_events = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
        return {
            "total_devices": total,
            "safe_devices": safe,
            "unverified_devices": unverified,
            "suspicious_devices": suspicious,
            "attack_devices": attacks,
            "quarantined_devices": quarantined,
            "blocked_devices": blocked,
            "total_events": total_events,
        }


def learn_environment():
    """Mark all currently active non-attack devices as baseline environment known."""
    with get_db() as conn:
        conn.execute("""
            UPDATE devices
            SET risk_score = 0,
                status = CASE 
                    WHEN status = 'ATTACK' THEN 'ATTACK' 
                    WHEN manufacturer != 'Unknown' THEN 'SAFE' 
                    ELSE 'UNVERIFIED' 
                END
            WHERE status != 'ATTACK' AND blocked = 0
        """)
        count = conn.execute("SELECT COUNT(*) as c FROM devices WHERE status != 'ATTACK'").fetchone()["c"]
        return count

