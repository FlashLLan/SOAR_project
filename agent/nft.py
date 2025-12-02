import subprocess

NFT_SET = "inet firewall blocklist4"

def block_ip(src_ip: str, duration_seconds: int = 120):
    """
    Add an IPv4 address to the dynamic blocklist4 set.
    If the IP is already present, delete it first so the timeout is reset.
    """
    # Try to delete existing element (ignore errors)
    del_cmd = f"sudo nft delete element {NFT_SET} '{{ {src_ip} }}'"
    subprocess.run(del_cmd, shell=True, capture_output=True, text=True)

    #  Add fresh element with new timeout
    add_cmd = (
        f"sudo nft add element {NFT_SET} "
        f"'{{ {src_ip} timeout {duration_seconds}s }}'"
    )

    print("[nft] running:", add_cmd)
    result = subprocess.run(add_cmd, shell=True, capture_output=True, text=True)

    print("[nft] rc =", result.returncode)
    if result.stderr:
        print("[nft] stderr:", result.stderr.strip())
