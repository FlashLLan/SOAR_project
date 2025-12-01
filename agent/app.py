from flask import Flask, jsonify
import threading
import yaml

from collector.db import init_db, get_last_alerts
from collector.tailer import start_tailer

app = Flask(__name__)

# Load config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

DB_PATH = config["database_path"]
EVE_PATH = config["eve_log_path"]

# Initialize DB
conn = init_db(DB_PATH)

# Background tailer thread
def run_tailer():
    start_tailer(EVE_PATH, conn)

tailer_thread = threading.Thread(target=run_tailer, daemon=True)
tailer_thread.start()

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/alerts")
def alerts():
    rows = get_last_alerts(conn, limit=50)
    return jsonify(rows)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
