import subprocess

NFT_SET = "inet firewall blocklist4"

def block_ip(src_ip: str, duration_seconds: int = 120):
    """
    Add an IPv4 address to the dynamic blocklist4 set.
    """
    cmd = f"sudo nft add element inet firewall blocklist4 '{{ {src_ip} timeout {duration_seconds}s }}'"

    print("[nft] running:", cmd)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    print("[nft] rc =", result.returncode)
    if result.stderr:
        print("[nft] stderr:", result.stderr.strip())
