#!/usr/bin/env python3
import argparse
import os
import sqlite3
import textwrap
import subprocess
import sys
import re
from typing import Optional
import json
from soar.firewall import nft
from soar.config import load_config

SOAR_VERSION = "1.3.0-cli"

NFT_CONF_PATH = "/etc/nftables.conf"

# ---------- DB helpers ----------

def get_db(db_path: str):
    conn = sqlite3.connect(db_path)
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
    cfg = load_config()
    db_path = cfg.database_path
    # ----- STATUS -----
    if args.action == "status":
        verbose = getattr(args, "verbose", False)

        # Collect everything in a dict first
        status = {
            "engine_running": False,
            "pids": [],
            "db_path": db_path,
            "alerts": None,
            "alerts_error": None,
            "last_alert": None,
            "blocklist_size": None,
            "blocklist_sample": [],
            "blocklist_error": None,
        }

        # Check if engine is running
        try:
            out = subprocess.check_output(
                ["pgrep", "-af", "soar.decision.engine"], text=True
            ).strip()
        except subprocess.CalledProcessError:
            out = ""

        if out:
            lines = out.splitlines()
            pids = [ln.split()[0] for ln in lines]
            status["engine_running"] = True
            status["pids"] = pids
        else:
            status["engine_running"] = False

        # Alert stats
        if os.path.exists(db_path):
            try:
                conn = get_db(db_path)
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

                status["alerts"] = {
                    "total": total,
                    "pending": pending,
                    "processed": processed,
                }

                last = cur.execute(
                    "SELECT id, timestamp, src_ip, signature_id "
                    "FROM alerts ORDER BY id DESC LIMIT 1"
                ).fetchone()

                if last:
                    status["last_alert"] = {
                        "id": last["id"],
                        "timestamp": last["timestamp"],
                        "src_ip": last["src_ip"],
                        "signature_id": last["signature_id"],
                    }

            except sqlite3.Error as e:
                status["alerts_error"] = str(e)
        else:
            status["alerts_error"] = "DB file not found"

        # Blocklist stats
        try:
            entries = nft.list_blocklist()
            count = len(entries)
            status["blocklist_size"] = count
            status["blocklist_sample"] = [e["ip"] for e in entries[:3]]
        except Exception as e:
            status["blocklist_error"] = str(e)

        # ---- JSON mode? ----
        if getattr(args, "json", False):
            print(json.dumps(status, indent=2))
            return

        # ---- Human readable output (what you had before, using status[]) ----
        print("SOAR Engine Status")
        print("------------------")

        if status["engine_running"]:
            first_pid = status["pids"][0]
            print(f"Engine process : RUNNING (PID {first_pid})")
            if verbose and len(status["pids"]) > 1:
                print("Other matches  :")
                for pid in status["pids"][1:]:
                    print(f"  {pid}")
        else:
            print("Engine process : NOT RUNNING")

        print(f"SQLite DB path : {status['db_path']}")

        if not verbose:
            return

        print("\n--- Engine / DB / blocklist stats ---")

        if status["alerts"]:
            print(f"Alerts total   : {status['alerts']['total']}")
            print(f"Pending alerts : {status['alerts']['pending']}")
            print(f"Processed      : {status['alerts']['processed']}")
        else:
            print(f"Alert stats    : unavailable ({status['alerts_error']})")

        if status["last_alert"]:
            la = status["last_alert"]
            print(
                "Last alert     : "
                f"id={la['id']} time={la['timestamp']} "
                f"src={la['src_ip']} sid={la['signature_id']}"
            )

        if status["blocklist_size"] is not None:
            print(f"Blocklist size : {status['blocklist_size']}")
            if status["blocklist_sample"]:
                sample = ", ".join(status["blocklist_sample"])
                if status["blocklist_size"] > len(status["blocklist_sample"]):
                    sample += ", …"
                print(f"Sample IPs     : {sample}")
        else:
            print(f"Blocklist      : stats unavailable ({status['blocklist_error']})")

        return

    # ----- START -----
    elif args.action == "start":

        if args.silent:
            # background mode
            print("Starting decision engine in background mode…")
            subprocess.Popen(
                ["python3", "-m", "soar.decision.engine"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print("Engine started (silent).")
        else:
            # foreground mode
            print("Starting decision engine (foreground mode)…")
            subprocess.call(["python3", "-m", "soar.decision.engine"])


    # ----- STOP -----
    elif args.action == "stop":
        try:
            out = subprocess.check_output(
                ["pgrep", "-af", "soar.decision.engine"], text=True
            ).strip()
        except subprocess.CalledProcessError:
            out = ""

        if not out:
            print("decision_engine.py is NOT running")
            return

        lines = out.splitlines()
        pids = [ln.split()[0] for ln in lines]
        for pid in pids:
            print(f"Stopping decision engine process {pid}…")
            subprocess.call(["kill", pid])

        print("Engine stopped.")

    else:
        raise SystemExit("Unknown engine action")

# ---------- alerts subcommand ----------

def cmd_alerts(args):
    cfg = load_config()
    conn = get_db(cfg.database_path)
    as_json = getattr(args, "json", False)

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

    if as_json:
        print(json.dumps([dict(r) for r in rows], indent=2))
        return

    if not rows:
        print("No matching alerts.")
        return

    for r in rows:
        sig_id = r["signature_id"] if "signature_id" in r.keys() else "-"
        print(f"[{r['id']}] {r['timestamp']} src={r['src_ip']} sig_id={sig_id}")

        sig = r["signature"] or ""
        sig = textwrap.shorten(sig, width=100, placeholder="…")
        print(f"    {sig}")

# ---------- blocklist subcommand ----------

def cmd_blocklist(args):
    as_json = getattr(args, "json", False)

    if args.action == "show":
        entries = nft.list_blocklist()

        if as_json:
            print(json.dumps(entries, indent=2))
            return

        if not entries:
            print("Blocklist is empty.")
            return

        print(f"{'IP':<18}  {'EXPIRES':<12} {'TIMEOUT':<8}")
        print("-" * 45)
        for e in entries:
            expires = e.get("expires") or "-"
            timeout = e.get("timeout") or "-"
            print(f"{e['ip']:<18}  {expires:<12}  {timeout:<8}")
        return

    elif args.action == "add":
        duration = args.duration or 300
        if as_json:
            print(json.dumps(
                {"status": "OK", "action": "add",
                 "ip": args.ip, "duration": duration},
                indent=2,
            ))
        else: print(
            f"Blocking {args.ip} for {duration} seconds "
            f"via nftables blocklist4…"
        )
        nft.block_ip(args.ip, duration)
        print("Done.")
    elif args.action == "remove":
        nft.unblock_ip(args.ip)
        if as_json:
            print(json.dumps({"status": "OK", "action": "remove", "ip": args.ip}, indent=2))
        else:
            print(f"Unblocking {args.ip} from nftables blocklist4…")
            print("Done.")
        return

    elif args.action == "clear":
        nft.clear_blocklist()
        if as_json:
            print(json.dumps(
                {"status": "OK", "action": "clear"},
                indent=2,
            ))
        else:
            print("Flushing all entries from nftables blocklist4…")
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

def _show_rollbacks(conn, limit: int, as_json: bool = False):
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
        if as_json:
            print("[]")
        else:
            print("No rollbacks recorded yet.")
        return

    if as_json:
        out = [dict(r) for r in rows]
        print(json.dumps(out, indent=2))
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
    cfg = load_config()
    conn = get_db(cfg.database_path)
    as_json = getattr(args, "json", False)

    # 1) If --last is given, just show history and exit
    if args.last:
        _show_rollbacks(conn, args.last, as_json=as_json)
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
    nft.unblock_ip(src_ip)

    # log to rollbacks table
    _insert_rollback(conn, alert_id, src_ip, args.reason)

    if as_json:
        print(json.dumps({
            "status": "OK",
            "ip": src_ip,
            "alert_id": alert_id,
            "reason": args.reason,
        }, indent=2))
    else:
        print(f"Rolling back: removing {src_ip} from blocklist4…")
        print("nftables updated.")
        print("Rollback logged to rollbacks table.")

# ---------- ifaces subcommand ----------

def cmd_ifaces(args):
    conf_path = args.conf or NFT_CONF_PATH
    as_json = getattr(args, "json", False)

    try:
        text = _read_nft_conf(conf_path)
    except FileNotFoundError:
        raise SystemExit(f"nftables config not found at {conf_path}")

    if args.action == "show":
        mapping = _parse_ifaces(text)
        if as_json:
            print(json.dumps(mapping, indent=2))
            return
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
        if as_json:
            mapping = _parse_ifaces(updated)
            print(json.dumps(
                {"conf": conf_path,
                 "changes": changes,
                 "mapping": mapping},
                indent=2,
            ))
            return

        print(f"Updated nftables interface defines in {conf_path}:")
        for c in changes:
            print(f"  {c}")
        print("\nRemember to reload nftables, for example:")
        print(f"  sudo nft -f {conf_path}")
        return

    else:
        raise SystemExit("Unknown ifaces action")

# -----------version----------------

def cmd_version(args):
    """Print SOAR CLI / agent version."""
    if getattr(args, "json", False):
        print(json.dumps({"version": SOAR_VERSION}, indent=2))
    else:
        print(f"SOAR lab router CLI version {SOAR_VERSION}")

# ----------- help fucntion for self-check------------
def find_engine_pid() -> Optional[str]:
    """Return PID of decision_engine.py or None if not running."""
    try:
        out = subprocess.check_output(
            ["pgrep", "-af", "soar.decision.engine"], text=True
        ).strip()
    except subprocess.CalledProcessError:
        return None

    if not out:
        return None

    first_line = out.splitlines()[0]
    return first_line.split()[0]

# ----------- self-check------------

def cmd_test(args):
    """
    Basic health checks:
      - SQLite DB reachable
      - eve.json readable
      - nftables blocklist set exists
      - decision_engine.py running or not
    """

    cfg = load_config()
    db_path = cfg.database_path
    eve_path = cfg.eve_log_path

    checks = []
    overall = "OK"

    # DB check
    db_result = {"component": "database"}
    try:
        os.stat(db_path)
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM alerts")
        total = c.fetchone()[0]
        conn.close()
        db_result["status"] = "OK"
        db_result["detail"] = f"db reachable ({total} alerts)"
    except Exception as e:
        db_result["status"] = "FAIL"
        db_result["detail"] = f"{e}"
        overall = "FAIL"
    checks.append(db_result)

    # eve.json check
    eve_result = {"component": "eve.json"}
    try:
        with open(eve_path, "r") as f:
            first = f.readline()
        if first.strip():
            eve_result["status"] = "OK"
            eve_result["detail"] = "readable, first line looks like JSON"
        else:
            eve_result["status"] = "WARN"
            eve_result["detail"] = "file is empty"
            if overall != "FAIL":
                overall = "WARN"
    except Exception as e:
        eve_result["status"] = "FAIL"
        eve_result["detail"] = f"{e}"
        overall = "FAIL"
    checks.append(eve_result)

    # nftables blocklist set
    nft_result = {"component": "nftables blocklist"}
    try:
        entries = nft.list_blocklist()
        nft_result["status"] = "OK"
        nft_result["detail"] = f"set exists ({len(entries)} entries)"
    except Exception as e:
        nft_result["status"] = "FAIL"
        nft_result["detail"] = f"{e}"
        overall = "FAIL"
    checks.append(nft_result)

    # engine running?
    engine_result = {"component": "decision_engine"}
    pid = find_engine_pid()
    if pid:
        engine_result["status"] = "OK"
        engine_result["detail"] = f"running (PID {pid})"
    else:
        engine_result["status"] = "WARN"
        engine_result["detail"] = "not running"
        if overall != "FAIL":
            overall = "WARN"
    checks.append(engine_result)

    if getattr(args, "json", False):
        print(json.dumps({"overall": overall, "checks": checks}, indent=2))
        return

    print("SOAR self-test")
    print("--------------")
    for c in checks:
        print(f"[{c['status']}] {c['component']}: {c['detail']}")
    print(f"\nOverall: {overall}")


# ---------- parse wiring ----------

def build_parser():
    description = (
        "SOAR operator CLI for your lab router.\n\n"
        "Use this tool to control the decision engine, inspect Suricata\n"
        "alerts, manage the dynamic nftables blocklist, and undo blocks\n"
        "(rollback) when you confirm a false positive."
    )

    epilog = textwrap.dedent(
        """
        Examples:
          # Engine
          soarctl engine status
          soarctl engine status -v
          soarctl --json engine status

          # Alerts
          soarctl alerts --last 20
          soarctl --json alerts --last 5
          soarctl alerts --signature-id 9002001
          soarctl alerts --src-ip 192.168.130.136

          # Blocklist / rollback
          soarctl blocklist show
          soarctl --json blocklist show
          soarctl blocklist add 192.168.130.136 --duration 600
          soarctl rollback --alert-id 123 --reason "false positive"
          soarctl --json rollback --last 5

          # nftables interface defines
          soarctl ifaces show
          soarctl --json ifaces show
          soarctl ifaces set --wan eth-wan --lan eth-lan --dmz eth-dmz

          # Version / self-test
          soarctl version
          soarctl --json version
          soarctl test
          soarctl --json test
        """
    )

    parser = argparse.ArgumentParser(
        prog="soarctl",
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )

    # global flags
    parser.add_argument(
        "--json",
        action="store_true",
        help="output machine-readable JSON (where supported)",
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

    # version
    p_ver = subparsers.add_parser("version", help="show SOAR/CLI version")
    p_ver.set_defaults(func=cmd_version)

    # test
    p_test = subparsers.add_parser(
        "test", help="run basic health checks (DB, eve.json, nftables, engine)"
    )
    p_test.set_defaults(func=cmd_test)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
