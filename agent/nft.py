import subprocess
import shlex
import re

NFT_SET_FAMILY = "inet"
NFT_SET_TABLE = "firewall"
NFT_SET_NAME = "blocklist4"


def _run_nft(cmd: str) -> str:
    """Run an nft command via sudo and return stdout as text."""
    full_cmd = f"sudo nft {cmd}"
    result = subprocess.run(
        shlex.split(full_cmd),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"nft failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def block_ip(src_ip: str, duration_seconds: int = 120) -> None:
    """
    Add an IPv4 address to the dynamic blocklist4 set.
    If the IP is already present, delete it first so the timeout is reset.
    """
    # 1) Try to delete existing element (ignore errors)
    del_cmd = (
        f"delete element {NFT_SET_FAMILY} {NFT_SET_TABLE} {NFT_SET_NAME} "
        f"{{ {src_ip} }}"
    )
    try:
        _run_nft(del_cmd)
    except RuntimeError:
        # no such element, that's fine
        pass

    # 2) Add fresh element with new timeout
    add_cmd = (
        f"add element {NFT_SET_FAMILY} {NFT_SET_TABLE} {NFT_SET_NAME} "
        f"{{ {src_ip} timeout {duration_seconds}s }}"
    )
    print("[nft] running:", f"sudo nft {add_cmd}")
    _run_nft(add_cmd)


def unblock_ip(src_ip: str) -> None:
    """
    Remove IP from blocklist set.

    nft: sudo nft delete element inet firewall blocklist4 { 1.2.3.4 }
    """
    cmd = (
        f"delete element {NFT_SET_FAMILY} {NFT_SET_TABLE} {NFT_SET_NAME} "
        f"{{ {src_ip} }}"
    )
    print("[nft] running:", f"sudo nft {cmd}")
    _run_nft(cmd)


def list_blocklist(raw: bool = False):
    """
    List current elements in blocklist set.

    If raw=True -> return plain nft output.
    Else -> parse into list of dicts: [{'ip': '1.2.3.4', 'timeout': '294s'}, ...]
    """
    out = _run_nft(
        f"list set {NFT_SET_FAMILY} {NFT_SET_TABLE} {NFT_SET_NAME}"
    )

    if raw:
        return out

    # crude parser; enough for typical nft output:
    # elements = { 1.2.3.4 timeout 294s, 5.6.7.8, ... }
    elements = []
    m = re.search(r"elements\s*=\s*{(.*?)}", out, re.S)
    if not m:
        return elements

    body = m.group(1)
    # split by comma, each chunk may look like:
    # " 1.2.3.4 timeout 294s" or " 5.6.7.8 "
    for chunk in body.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        ip = parts[0]
        timeout = None
        if "timeout" in parts:
            idx = parts.index("timeout")
            if idx + 1 < len(parts):
                timeout = parts[idx + 1]
        elements.append({"ip": ip, "timeout": timeout})

    return elements
