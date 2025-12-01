import sqlite3
from pathlib import Path
import os

def get_db(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    return conn

def init_db(db_path):
    db_exists = Path(db_path).exists()
    conn = get_db(db_path)

    if not db_exists:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE alerts (
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
                severity INTEGER
            );
        """)
        conn.commit()

    return conn

def insert_alert(conn, alert):
    c = conn.cursor()
    c.execute("""
        INSERT INTO alerts (
            timestamp, src_ip, src_port, dest_ip, dest_port,
            proto, signature, signature_id, category, severity
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        alert.get("severity")
    ))
    conn.commit()

def get_last_alerts(conn, limit=50):
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    return c.fetchall()
