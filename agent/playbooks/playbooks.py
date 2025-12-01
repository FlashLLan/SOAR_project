from datetime import datetime, timedelta

from collector import db      # SQLite helpers live in collector/db.py
import nft    
# Default block durations (you can tune these)
SSH_BLOCK_SEC   = 600         # 10 min
ICMP_BLOCK_SEC  = 300         # 5  min
SYN_BLOCK_SEC   = 300         # 5  min
GENERIC_BLOCK_SEC = 120       # 2  min


def _record_action(conn, src_ip, reason, sid, blocked_until, status="blocked"):
    """Helper: insert a row into actions table."""
    c = conn.cursor()
    now = datetime.utcnow().isoformat()
    c.execute("""
        INSERT INTO actions (
            src_ip, reason, sid,
            first_seen, last_seen,
            count, blocked_until, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        src_ip,
        reason,
        sid,
        now,            # first_seen
        now,            # last_seen
        1,              # count (MVP)
        blocked_until,
        status
    ))
    conn.commit()


# --- Playbooks -------------------------------------------------------------
def handle_ssh_bruteforce(conn, alert_row):
    """
    Block SSH brute force attempts.
    Triggered by Suricata SIDs 9001001 (alert) / 9101001 (drop).
    """
    sid = int(alert_row["signature_id"])
    if sid not in (9001001, 9101001):
        return None

    src_ip = alert_row["src_ip"]
    nft.block_ip(src_ip, SSH_BLOCK_SEC)

    blocked_until = (datetime.utcnow() + timedelta(seconds=SSH_BLOCK_SEC)).isoformat()

    db.mark_alert_processed(
        conn,
        alert_id=alert_row["id"],
        decision=f"blocked ssh brute-force from {src_ip}",
        blocked_until=blocked_until,
    )


    # Log action
    _record_action(
        conn,
        src_ip=src_ip,
        reason="SSH brute-force",
        sid=sid,
        blocked_until=blocked_until,
    )

    return "blocked-ssh"


def handle_icmp_flood(conn, alert_row):
    """
    Block ICMP flood.
    Triggered by SID 9002001 (alert) / 9102001 (drop).
    """
    sid = int(alert_row["signature_id"])
    if sid not in (9002001, 9102001):
        return None

    src_ip = alert_row["src_ip"]
    nft.block_ip(src_ip, ICMP_BLOCK_SEC)

    blocked_until = (datetime.utcnow() + timedelta(seconds=ICMP_BLOCK_SEC)).isoformat()

    db.mark_alert_processed(
        conn,
        alert_id=alert_row["id"],
        decision=f"blocked icmp flood from {src_ip}",
        blocked_until=blocked_until,
    )

    _record_action(
        conn,
        src_ip=src_ip,
        reason="ICMP flood",
        sid=sid,
        blocked_until=blocked_until,
    )

    return "blocked-icmp"


def handle_syn_spike(conn, alert_row):
    """
    Block DoS SYN spike.
    Triggered by SID 9001011 (alert) / 9101011 (drop).
    """
    sid = int(alert_row["signature_id"])
    if sid not in (9001011, 9101011):
        return None

    src_ip = alert_row["src_ip"]
    nft.block_ip(src_ip, SYN_BLOCK_SEC)

    blocked_until = (datetime.utcnow() + timedelta(seconds=SYN_BLOCK_SEC)).isoformat()

    db.mark_alert_processed(
        conn,
        alert_id=alert_row["id"],
        decision=f"blocked syn spike from {src_ip}",
        blocked_until=blocked_until,
    )
    _record_action(
        conn,
        src_ip=src_ip,
        reason="SYN spike DoS",
        sid=sid,
        blocked_until=blocked_until,
    )

    return "blocked-syn-spike"


def handle_any_ip_alert(conn, alert_row):
    """
    Generic backstop playbook for very broad rule 'ANY IP ALERT' (SID 9900102).
    You can tune this or disable if it's too aggressive.
    """
    sid = alert_row["signature_id"]
    if sid != 9900102:
        return None

    src_ip = alert_row["src_ip"]

    nft.block_ip(src_ip, GENERIC_BLOCK_SEC)

    blocked_until_dt = datetime.utcnow() + timedelta(seconds=GENERIC_BLOCK_SEC)
    blocked_until = blocked_until_dt.isoformat()

    db.mark_alert_processed(
        conn,
        alert_id=alert_row["id"],
        decision=f"generic block from ANY IP ALERT: {src_ip}",
        blocked_until=blocked_until,
    )

    _record_action(
        conn,
        src_ip=src_ip,
        reason="Generic ANY IP ALERT block",
        sid=sid,
        blocked_until=blocked_until,
    )

    return "blocked-generic-any-ip"


# --- Dispatcher ------------------------------------------------------------

PLAYBOOKS = (
    handle_ssh_bruteforce,
    handle_icmp_flood,
    handle_syn_spike,
    #handle_any_ip_alert,
)


def run_playbooks(conn, alert_row):
    """
    Try each playbook until one handles this alert.
    Returns a string describing the action, or 'no-playbook'.
    """
    for pb in PLAYBOOKS:
        result = pb(conn, alert_row)
        if result is not None:
            return result

    # Nothing matched: just mark as processed without action
    db.mark_alert_processed(
        conn,
        alert_id=alert_row["id"],
        decision="no-playbook",
        blocked_until=None,
    )
    return "no-playbook"
