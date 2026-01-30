import sqlite3
import time
import yaml
from soar.config import load_config
from soar import db
from soar.playbooks.playbooks import run_playbooks

cfg = load_config()
DB_PATH = cfg.database_path

def process_batch(conn):
    rows = db.get_new_alerts(conn, limit=100)
    if not rows:
        return 0

    count = 0
    for row in rows:
        result = run_playbooks(conn, row)
        print(f"[decision] alert_id={row['id']} -> {result}")
        count += 1
    return count

def main_loop():
    cfg = load_config()
    print("[decision] Starting decision engine...")
    conn = db.init_db(cfg.database_path)

    while True:
        try:
            processed = process_batch(conn)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                print("[decision] DB is locked, retrying in 1s...")
                time.sleep(1)
                continue
            raise

        time.sleep(2 if processed == 0 else 0.2)

if __name__ == "__main__":
    main_loop()
