#!/usr/bin/env python3
import argparse
import os
import sqlite3
import textwrap
import subprocess
import sys
from typing import Optional

import nft 


DB_PATH = os.environ.get("SOAR_DB_PATH", "/root/soar-agent/alerts.db")


# ---------- DB helpers ----------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    return conn


def ensure_schema(conn):
    # only rollbacks; alerts table already exists
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rollbacks (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id   INTEGER,
            src_ip     TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            reason     TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
        """
    )
    conn.commit()


# ---------- engine subcommand ----------

def cmd_engine(args):
    if args.action == "status":
        # very simple: check if decision_engine.py is running
        try:
            out = subprocess.check_output(
                ["pgrep", "-af", "decision_engine.py"],
                text=True,
            ).strip()
        except subprocess.CalledProcessError:
            out = ""

        if not out:
            print("decision_engine.py is NOT running")
        else:
            print("decision_engine.py is running:")
            print(out)

    elif args.action == "start":
        # lightweight stub – you can wire this to systemd later
        print(
            "Engine start is not fully wired.\n"
            "Run it manually for now, e.g.:"
        )
        print("  python3 /path/to/decision_engine.py &")
    else:
        raise SystemExit("Unknown engine action")


# ---------- alerts subcommand ----------

def cmd_alerts(args):
    conn = get_db()
    query = (
        "SELECT id, timestamp, src_ip, signature_id, signature "
        "FROM alerts"
    )
    where = []
    params = []

    if args.src_ip:
        where.append("src_ip = ?")
        params.append(args.src_ip)

    if args.signature_id:
        where.append("signature_id = ?")
        params.append(args.signature_id)

    if args.signature:
        where.append("signature LIKE ?")
        params.append(f"%{args.signature}%")

    if where:
        query += " WHERE " + " AND ".join(where)

    query += " ORDER BY id DESC"

    if args.last:
        query += " LIMIT ?"
        params.append(args.last)

    rows = conn.execute(query, params).fetchall()
    if not rows:
        print("No matching alerts.")
        return

    for r in rows:
        cols = r.keys()
        sig_id = r["signature_id"] if "signature_id" in cols else "-"
        print(
            f"[{r['id']}] {r['timestamp']} src={r['src_ip']} "
            f"sig_id={sig_id}"
        )

        # keep signature text on its own line to stay short
        sig = r["signature"] or ""
        sig = textwrap.shorten(sig, width=100, placeholder="…")
        print(f"    {sig}")


# ---------- blocklist subcommand ----------

def cmd_blocklist(args):
    if args.action == "show":
        entries = nft.list_blocklist()
        if not entries:
            print("Blocklist is empty.")
            return
        print(f"{'IP':<18}  {'EXPIRES':<12} {'TIMEOUT':<8}")
        print("-" * 45)
        for e in entries:
            expires = e.get("expires") or "-"
            timeout = e.get("timeout") or "-"
            print(f"{e['ip']:<18}  {expires:<12}  {timeout:<8}")
    elif args.action == "add":
        duration = args.duration or 300
        print(
            f"Blocking {args.ip} for {duration} seconds "
            f"via nftables blocklist4…"
        )
        nft.block_ip(args.ip, duration)
        print("Done.")
    elif args.action == "remove":
        print(f"Unblocking {args.ip} from nftables blocklist4…")
        nft.unblock_ip(args.ip)
        print("Done.")
    else:
        raise SystemExit("Unknown blocklist action")


# ---------- rollback subcommand ----------

def _insert_rollback(conn, alert_id: Optional[int], src_ip: str, reason: str):
    conn.execute(
        "INSERT INTO rollbacks (alert_id, src_ip, reason) VALUES (?, ?, ?)",
        (alert_id, src_ip, reason or None),
    )
    conn.commit()


def cmd_rollback(args):
    if bool(args.ip) == bool(args.alert_id):
        raise SystemExit(
            "You must specify exactly one of --ip or --alert-id."
        )

    conn = get_db()

    if args.alert_id:
        # find src_ip for that alert
        row = conn.execute(
            "SELECT src_ip FROM alerts WHERE id = ?",
            (args.alert_id,),
        ).fetchone()
        if not row:
            raise SystemExit(
                f"No alert with id {args.alert_id} found in alerts table."
            )
        src_ip = row["src_ip"]
        alert_id = args.alert_id
    else:
        src_ip = args.ip
        alert_id = None

    # nftables rollback
    print(f"Rolling back: removing {src_ip} from blocklist4…")
    nft.unblock_ip(src_ip)
    print("nftables updated.")

    # log to rollbacks table
    _insert_rollback(conn, alert_id, src_ip, args.reason)
    print("Rollback logged to rollbacks table.")


# ---------- parse wiring ----------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="soarctl",
        description="SOAR operator CLI (engine, alerts, blocklist, rollback).",
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # engine
    p_engine = subparsers.add_parser("engine", help="engine control")
    p_engine_sub = p_engine.add_subparsers(
        dest="action", required=True
    )
    p_engine_status = p_engine_sub.add_parser(
        "status", help="show if decision_engine.py is running"
    )
    p_engine_status.set_defaults(func=cmd_engine)
    p_engine_start = p_engine_sub.add_parser(
        "start", help="start decision engine (stub)"
    )
    p_engine_start.set_defaults(func=cmd_engine)

    # alerts
    p_alerts = subparsers.add_parser(
        "alerts", help="inspect alerts stored in SQLite"
    )
    p_alerts.add_argument(
        "--last",
        type=int,
        help="show only most recent N alerts",
    )
    p_alerts.add_argument(
        "--src-ip",
        help="filter by source IP",
    )
    p_alerts.add_argument(
        "--signature-id",
        type=int,
        help="filter by signature_id",
    )
    p_alerts.add_argument(
        "--signature",
        help="filter by signature text (LIKE %text%)",
    )
    p_alerts.set_defaults(func=cmd_alerts)

    # blocklist
    p_block = subparsers.add_parser(
        "blocklist", help="manage nftables blocklist4 set"
    )
    p_block_sub = p_block.add_subparsers(
        dest="action", required=True
    )

    p_block_show = p_block_sub.add_parser(
        "show", help="list current blocklist entries"
    )
    p_block_show.set_defaults(func=cmd_blocklist)

    p_block_add = p_block_sub.add_parser(
        "add", help="add IP to blocklist4"
    )
    p_block_add.add_argument("ip", help="source IP to block")
    p_block_add.add_argument(
        "--duration",
        type=int,
        help="block duration in seconds (default 300)",
    )
    p_block_add.set_defaults(func=cmd_blocklist)

    p_block_remove = p_block_sub.add_parser(
        "remove", help="remove IP from blocklist4"
    )
    p_block_remove.add_argument("ip", help="source IP to unblock")
    p_block_remove.set_defaults(func=cmd_blocklist)

    # rollback
    p_rb = subparsers.add_parser(
        "rollback", help="undo a block and log it"
    )
    p_rb.add_argument(
        "--ip",
        help="IP to rollback (remove from blocklist4)",
    )
    p_rb.add_argument(
        "--alert-id",
        type=int,
        help="alert ID whose src IP should be rolled back",
    )
    p_rb.add_argument(
        "--reason",
        help="reason / comment to store in DB",
        default="",
    )
    p_rb.set_defaults(func=cmd_rollback)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
