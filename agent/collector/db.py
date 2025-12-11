import sqlite3
from pathlib import Path
from datetime import datetime

def get_db(db_path):
    # Add timeout and enable WAL for better read/write concurrency
    conn = sqlite3.connect(db_path, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db(db_path):
    db_exists = Path(db_path).exists()
    conn = get_db(db_path)
    c = conn.cursor()

    # alerts table – now includes "status", "decision", etc.
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        src_port TEXT,
        dest_ip TEXT,
        dest_port TEXT,
        proto TEXT,
        signature TEXT,
        signature_id INTEGER,
        category TEXT,
        severity INTEGER,
        status TEXT DEFAULT 'new',      -- new | processed
        decision TEXT,                  -- what playbook decided
        blocked_until TEXT,             -- ISO time when block expires
        processed_at TEXT               -- when decision was made
    );
    """)

    # actions table – history of actions we took
    c.execute("""
    CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        src_ip TEXT NOT NULL,
        reason TEXT NOT NULL,
        sid INTEGER,
        first_seen TEXT,
        last_seen TEXT,
        count INTEGER,
        blocked_until TEXT,
        status TEXT
    );
    """)

    conn.commit()
    return conn


def insert_alert(conn, alert):
    """Store a fresh alert from Suricata."""
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (
            timestamp, src_ip, src_port, dest_ip, dest_port,
            proto, signature, signature_id, category, severity,
            status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new')
    """, (
        alert.get("timestamp"),
        alert.get("src_ip"),
        alert.get("src_port"),
        alert.get("dest_ip"),
        alert.get("dest_port"),
        alert.get("proto"),
        alert.get("signature"),
        alert.get("signature_id"),
        alert.get("category"),
        alert.get("severity"),
    ))
    conn.commit()


def get_new_alerts(conn, limit=100):
    """Return alerts that were not processed yet."""
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        """
        SELECT * FROM alerts
        WHERE status='new'
          AND (processed_at IS NULL OR processed_at = '')
        ORDER BY id ASC LIMIT ?
        """,
        (limit,),
    )
    return c.fetchall()


def mark_alert_processed(conn, alert_id, decision, blocked_until=None):
    """Mark alert as processed and store decision."""
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute(
        """
        UPDATE alerts
        SET status='processed',
            decision=?,
            blocked_until=?,
            processed_at=?
        WHERE id=?
        """,
        (decision, blocked_until, now, alert_id),
    )
    conn.commit()

def get_last_alerts(conn, limit=50):
    """Return the most recent alerts for the /alerts API."""
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    # convert sqlite Row -> plain dicts so Flask can jsonify them
    return [dict(r) for r in rows]
