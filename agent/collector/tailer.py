import json
import time
import os

from .models import parse_alert
from .db import insert_alert

def tail_file(path):
    """Generator that yields new lines as they appear."""
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)  # go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line

def start_tailer(eve_path, conn):
    print(f"[TAILER] Watching {eve_path} ...")

    for line in tail_file(eve_path):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        if "alert" in record:
            alert = parse_alert(record)
            insert_alert(conn, alert)
            print(f"[TAILER] Stored alert: {alert['signature']}")
