#!/usr/bin/env python3
import argparse
import os
import sqlite3
import textwrap
import subprocess
import sys
import re
from typing import Optional

import nft


PROJECT_ROOT = "/root/soar-agent"
ENGINE_SCRIPT = os.path.join(PROJECT_ROOT, "decision_engine.py")

DB_PATH = os.environ.get("SOAR_DB_PATH", "/root/soar-agent/alerts.db")

NFT_CONF_PATH = os.environ.get("SOAR_NFT_PATH", "/etc/nftables.conf")


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

# ---------- nftables interface helpers ----------

IFACE_DEFINES = ["WAN", "LAN", "DMZ"]


def _read_nft_conf(path: str) -> str:
    with open(path, "r") as f:
        return f.read()


def _write_nft_conf(path: str, text: str) -> None:
    with open(path, "w") as f:
        f.write(text)


def _parse_ifaces(text: str):
    """
    Return intrefaces like {'WAN': 'eth-wan', 'LAN': 'eth-lan', 'DMZ': 'eth-dmz'}
    based on 'define NAME = "iface"' lines.
    """
    mapping = {}
    for name in IFACE_DEFINES:
        m = re.search(rf'^define\s+{name}\s*=\s*"([^"]+)"', text, re.M)
        if m:
            mapping[name] = m.group(1)
    return mapping


def _set_iface(text: str, name: str, value: str) -> str:
    """
    Replace the define line for NAME with the new value.
    If the define is missing, prepend it at the top.
    """
    pattern = rf'^(define\s+{name}\s*=\s*")([^"]+)(".*)$'

    def repl(m):
        return m.group(1) + value + m.group(3)

    new_text, n = re.subn(pattern, repl, text, flags=re.M)
    if n == 0:
        # If not found, insert near the top (after 'flush ruleset' if present)
        lines = new_text.splitlines()
        inserted = False
        for i, line in enumerate(lines):
            if line.strip().startswith("define "):
                lines.insert(i, f'define {name} = "{value}"')
                inserted = True
                break
        if not inserted:
            lines.insert(0, f'define {name} = "{value}"')
        new_text = "\n".join(lines) + "\n"
    return new_text


# ---------- engine subcommand ----------

def cmd_engine(args):
    """Engine subcommand: status / start / stop."""

    # ----- STATUS -----
    if args.action == "status":
        verbose = getattr(args, "verbose", False)

        print("SOAR Engine Status")
        print("------------------")

        # Check if engine is running
        try:
            out = subprocess.check_output(
                ["pgrep", "-af", "decision_engine.py"], text=True
            ).strip()
        except subprocess.CalledProcessError:
            out = ""

        if out:
            lines = out.splitlines()
            first_pid = lines[0].split()[0]
            print(f"Engine process : RUNNING (PID {first_pid})")
            if verbose and len(lines) > 1:
                print("Other matches  :")
                for ln in lines[1:]:
                    print(f"  {ln}")
        else:
            print("Engine process : NOT RUNNING")

        # Always show paths
        print(f"SQLite DB path : {DB_PATH}")
        print(f"nftables.conf  : {NFT_CONF_PATH}")

        if not verbose:
            return

        print("\n--- Engine / DB / blocklist stats ---")

        # Alert stats
        if os.path.exists(DB_PATH):
            try:
                conn = get_db()
                cur = conn.cursor()

                total = cur.execute(
                    "SELECT COUNT(*) FROM alerts"
                ).fetchone()[0]

                pending = cur.execute(
                    "SELECT COUNT(*) FROM alerts WHERE status='new'"
                ).fetchone()[0]

                processed = cur.execute(
                    "SELECT COUNT(*) FROM alerts WHERE status='processed'"
                ).fetchone()[0]

                print(f"Alerts total   : {total}")
                print(f"Pending alerts : {pending}")
                print(f"Processed      : {processed}")

                last = cur.execute(
                    "SELECT id, timestamp, src_ip, signature_id "
                    "FROM alerts ORDER BY id DESC LIMIT 1"
                ).fetchone()

                if last:
                    print(
                        "Last alert     : "
                        f"id={last['id']} time={last['timestamp']} "
                        f"src={last['src_ip']} sid={last['signature_id']}"
                    )

            except sqlite3.Error as e:
                print(f"Alert stats    : unavailable ({e})")
        else:
            print("Alert stats    : DB file not found")

        # Blocklist stats
        try:
            entries = nft.list_blocklist()
            count = len(entries)
            print(f"Blocklist size : {count}")
            if count:
                sample = ", ".join(e["ip"] for e in entries[:3])
                if count > 3:
                    sample += ", …"
                print(f"Sample IPs     : {sample}")
        except Exception as e:
            print(f"Blocklist      : stats unavailable ({e})")

        return

    # ----- START -----
    elif args.action == "start":
        engine_path = ENGINE_SCRIPT

        if args.silent:
            # background mode
            print("Starting decision engine in background mode…")
            subprocess.Popen(
                ["python3", engine_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print("Engine started (silent).")
        else:
            # foreground mode
            print("Starting decision engine (foreground mode)…")
            subprocess.call(["python3", engine_path])

    # ----- STOP -----
    elif args.action == "stop":
        try:
            out = subprocess.check_output(
                ["pgrep", "-f", "decision_engine.py"], text=True
            ).strip()
        except subprocess.CalledProcessError:
            out = ""

        if not out:
            print("decision_engine.py is NOT running")
            return

        pids = out.splitlines()
        for pid in pids:
            print(f"Stopping decision engine process {pid}…")
            subprocess.call(["kill", pid])

        print("Engine stopped.")

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

    elif args.action == "clear":
        print("Flushing all entries from nftables blocklist4…")
        nft.clear_blocklist()
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

def _show_rollbacks(conn, limit: int):
    rows = conn.execute(
        """
        SELECT
            r.id,
            r.created_at,
            r.src_ip,
            r.reason,
            r.alert_id,
            a.signature_id,
            a.signature
        FROM rollbacks r
        LEFT JOIN alerts a ON a.id = r.alert_id
        ORDER BY r.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    if not rows:
        print("No rollbacks recorded yet.")
        return

    for r in rows:
        print(
            f"[{r['id']}] {r['created_at']} src={r['src_ip']} "
            f"alert_id={r['alert_id'] or '-'} "
            f"sig_id={r['signature_id'] or '-'}"
        )

        reason = r["reason"] or ""
        if reason:
            print(f"    reason: {reason}")

        sig = r["signature"] or ""
        if sig:
            sig = textwrap.shorten(sig, width=100, placeholder="…")
            print(f"    alert:  {sig}")


def cmd_rollback(args):
    conn = get_db()

    # 1) If --last is given, just show history and exit
    if args.last:
        _show_rollbacks(conn, args.last)
        return

    # 2) Normal rollback path: require exactly one of --ip / --alert-id
    if bool(args.ip) == bool(args.alert_id):
        raise SystemExit(
            "You must specify exactly one of --ip or --alert-id."
        )

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


# ---------- ifaces subcommand ----------

def cmd_ifaces(args):
    conf_path = args.conf or NFT_CONF_PATH

    try:
        text = _read_nft_conf(conf_path)
    except FileNotFoundError:
        raise SystemExit(f"nftables config not found at {conf_path}")

    if args.action == "show":
        mapping = _parse_ifaces(text)
        if not mapping:
            print(f"No define WAN/LAN/DMZ lines found in {conf_path}")
            return

        print(f"Interface defines in {conf_path}:")
        for name in IFACE_DEFINES:
            val = mapping.get(name, "<missing>")
            print(f"  {name} = {val}")
        return

    elif args.action == "set":
        updated = text
        changes = []

        if args.wan:
            updated = _set_iface(updated, "WAN", args.wan)
            changes.append(f"WAN={args.wan}")
        if args.lan:
            updated = _set_iface(updated, "LAN", args.lan)
            changes.append(f"LAN={args.lan}")
        if args.dmz:
            updated = _set_iface(updated, "DMZ", args.dmz)
            changes.append(f"DMZ={args.dmz}")

        if not changes:
            print("Nothing to change: specify at least one of --wan/--lan/--dmz.")
            return

        _write_nft_conf(conf_path, updated)
        print(f"Updated nftables interface defines in {conf_path}:")
        for c in changes:
            print(f"  {c}")
        print("\nRemember to reload nftables, for example:")
        print(f"  sudo nft -f {conf_path}")
        return

    else:
        raise SystemExit("Unknown ifaces action")


# ---------- parse wiring ----------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="soarctl",
        description=(
            "SOAR operator CLI for your lab router.\n\n"
            "Use this tool to control the decision engine, inspect Suricata\n"
            "alerts, manage the dynamic nftables blocklist, and undo blocks\n"
            "(rollback) when you confirm a false positive."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              # Engine
              soarctl engine status -v
              soarctl engine start --silent
              soarctl engine stop

              # Alerts
              soarctl alerts --last 20
              soarctl alerts --signature-id 9002001
              soarctl alerts --src-ip 192.168.130.136

              # Blocklist / rollback
              soarctl blocklist show
              soarctl blocklist clear
              soarctl blocklist add 192.168.130.136 --duration 600
              soarctl rollback --alert-id 123 --reason "false positive"
              soarctl rollback --ip 192.168.130.136 --reason "testing"
 
              # nftables interface defines
              soarctl ifaces show
              soarctl ifaces set --wan eth-wan --lan eth-lan --dmz eth-dmz
            """
        ),
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
    p_engine_status.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="include DB and blocklist statistics in status output",
    )
    p_engine_status.set_defaults(func=cmd_engine)
 
    p_engine_start = p_engine_sub.add_parser(
        "start", help="start decision engine"
    )
    p_engine_start.add_argument(
        "--silent",
        action="store_true",
        help="run engine in background (no output)"
    )
    p_engine_start.set_defaults(func=cmd_engine)

    p_engine_stop = p_engine_sub.add_parser(
        "stop", help="stop the running decision engine"
    )
    p_engine_stop.set_defaults(func=cmd_engine)

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

    p_block_clear = p_block_sub.add_parser(
        "clear", help="flush all entries from blocklist4"
    )
    p_block_clear.set_defaults(func=cmd_blocklist)

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
    p_rb.add_argument(
        "--last",
        type=int,
        help="show last N rollbacks instead of performing a new rollback",
    )

    p_rb.set_defaults(func=cmd_rollback)

    # ifaces
    p_if = subparsers.add_parser(
        "ifaces", help="view/update nftables interface defines (WAN/LAN/DMZ)"
    )
    p_if.add_argument(
        "--conf",
        default=NFT_CONF_PATH,
        help=f"path to nftables.conf (default: {NFT_CONF_PATH})",
    )
    p_if_sub = p_if.add_subparsers(dest="action", required=True)

    p_if_show = p_if_sub.add_parser(
        "show", help="show current interface names"
    )
    p_if_show.set_defaults(func=cmd_ifaces)

    p_if_set = p_if_sub.add_parser(
        "set", help="set interface names in nftables.conf"
    )
    p_if_set.add_argument("--wan", help="interface name for WAN")
    p_if_set.add_argument("--lan", help="interface name for LAN")
    p_if_set.add_argument("--dmz", help="interface name for DMZ")
    p_if_set.set_defaults(func=cmd_ifaces)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
