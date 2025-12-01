# nft.py – VERY simple helper for now
import subprocess

TABLE = "inet"
FAMILY_TABLE = "firewall"
SET_NAME = "blocklist4"

def block_ip(src_ip: str, duration_seconds: int):
    """
    Add IP to firewall blocklist4 set with timeout.
    Assumes your nftables ruleset already has:
      set blocklist4 { type ipv4_addr; flags interval,timeout; timeout 30d; }
    """
    timeout = f"{duration_seconds}s"
    cmd = [
        "nft", "add", "element", f"{TABLE} {FAMILY_TABLE} {SET_NAME}",
        f"{{ {src_ip} timeout {timeout} }}",
    ]
    subprocess.run(cmd, check=False)
