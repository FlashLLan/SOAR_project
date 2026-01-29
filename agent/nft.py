import subprocess
import shlex
import re

NFT_SET_FAMILY = "inet"
NFT_SET_TABLE = "soar"
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
    If the IP is already gone (timeout or previously removed),
    ignore the nft error.
    nft: sudo nft delete element inet firewall blocklist4 { 1.2.3.4 }
    """
    cmd = (
        f"delete element {NFT_SET_FAMILY} {NFT_SET_TABLE} {NFT_SET_NAME} "
        f"{{ {src_ip} }}"
    )
    print("[nft] running:", f"sudo nft {cmd}")
    try:
        _run_nft(cmd)
    except RuntimeError as e:
        if "No such file or directory" in str(e):
            print("[nft] IP not present in set anymore.")
        else:
            raise

def list_blocklist(raw: bool = False):
    """
    List current elements in blocklist set.

    If raw=True -> return plain nft output.
    Else -> parse into list of dicts: [{'ip': '1.2.3.4', 'timeout': '294s'}, ...]
        [{'ip': '1.2.3.4', 'timeout': '1m', 'expires': '40s608ms'}, ...]
    """
    out = _run_nft(
        f"list set {NFT_SET_FAMILY} {NFT_SET_TABLE} {NFT_SET_NAME}"
    )

    if raw:
        return out

    elements = []
    m = re.search(r"elements\s*=\s*{(.*?)}", out, re.S)
    if not m:
        return elements

    body = m.group(1)

    for chunk in body.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        parts = chunk.split()
        ip = parts[0]
        timeout = None
        expires = None

        if "timeout" in parts:
            idx = parts.index("timeout")
            if idx + 1 < len(parts):
                timeout = parts[idx + 1]

        if "expires" in parts:
            idx = parts.index("expires")
            if idx + 1 < len(parts):
                expires = parts[idx + 1]

        elements.append({"ip": ip, "timeout": timeout, "expires": expires})

    return elements

def clear_blocklist() -> None:
    """
    Remove all elements from the blocklist set.
    Equivalent to: sudo nft flush set inet firewall blocklist4
    """
    cmd = (
        f"flush set {NFT_SET_FAMILY} {NFT_SET_TABLE} {NFT_SET_NAME}"
    )
    print("[nft] running:", f"sudo nft {cmd}")
    try:
        _run_nft(cmd)
    except RuntimeError as e:
        # If set doesn't exist or is already empty, ignore
        if "No such file or directory" in str(e):
            print("[nft] blocklist set empty or missing, ignoring.")
        else:
            raise
