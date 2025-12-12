import sqlite3
import time
import yaml
from collector import db
from playbooks.playbooks import run_playbooks

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

DB_PATH = "/root/soar-agent/alerts.db"   


def process_batch(conn):
    """
    Process all new alerts from SQLite by applying playbooks.
    Returns number of processed alerts.
    """
    rows = db.get_new_alerts(conn, limit=100)
    if not rows:
        return 0

    count = 0
    for row in rows:
        result = run_playbooks(conn, row)
        print(f"[decision] alert_id={row['id']} -> {result}")

        db.mark_alert_processed(conn, row["id"], result)

        count += 1

    return count


def main_loop():
    """Continuous decision loop."""
    print("[decision] Starting decision engine...")
    conn = db.init_db(DB_PATH)

    while True:
        try:
            processed = process_batch(conn)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                print("[decision] DB is locked, retrying in 1s...")
                time.sleep(1)
                continue
            else:
                # future errors
                raise

        if processed == 0:
            # Nothing to do, relax to reduce CPU load
            time.sleep(2)
        else:
            # If many alerts are incoming, process again quickly
            time.sleep(0.2)


if __name__ == "__main__":
    main_loop()
