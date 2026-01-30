#!/usr/bin/env bash
set -euo pipefail

# -------- helpers --------
msg() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./uninstall.sh"
  exit 1
fi

# Try to detect venv and install dir from /usr/local/bin/soarctl symlink
SOARCTL_LINK="/usr/local/bin/soarctl"
VENV_BIN=""
INSTALL_DIR=""

if [[ -L "$SOARCTL_LINK" ]]; then
  TARGET="$(readlink -f "$SOARCTL_LINK" || true)"
  # expected: /opt/soar/venv/bin/soarctl  OR  /home/user/.../venv/bin/soarctl
  if [[ "$TARGET" == */venv/bin/soarctl ]]; then
    VENV_BIN="$(dirname "$TARGET")"            # .../venv/bin
    INSTALL_DIR="$(dirname "$(dirname "$(dirname "$TARGET")")")"  # ... (3 levels up) => /opt/soar
  fi
fi

# Fallback guess
if [[ -z "$INSTALL_DIR" ]]; then
  # If you standardize to /opt/soar going forward, this is fine:
  INSTALL_DIR="/opt/soar"
fi

msg "Detected install dir: $INSTALL_DIR"
msg "Detected venv bin: ${VENV_BIN:-"(none)"}"

# -------- 1) stop/disable services --------
msg "Stopping/disabling systemd services (if present)"
systemctl stop soar-engine.service 2>/dev/null || true
systemctl disable soar-engine.service 2>/dev/null || true

# Optional
systemctl stop soar-collector.service 2>/dev/null || true
systemctl disable soar-collector.service 2>/dev/null || true

# -------- 2) remove systemd units --------
msg "Removing systemd unit files"
rm -f /etc/systemd/system/soar-engine.service
rm -f /etc/systemd/system/soar-collector.service
systemctl daemon-reload

# -------- 3) remove global CLI --------
msg "Removing $SOARCTL_LINK"
rm -f "$SOARCTL_LINK"
hash -r 2>/dev/null || true

# -------- 4) nftables cleanup --------
msg "Cleaning nftables SOAR artifacts"
# Remove SOAR include file
rm -f /etc/nftables.d/soar.nft

# Restore nftables.conf if init made a backup
if [[ -f /etc/nftables.conf.bak ]]; then
  msg "Restoring /etc/nftables.conf from /etc/nftables.conf.bak"
  cp -f /etc/nftables.conf.bak /etc/nftables.conf
else
  # If no backup exists, do NOT try to delete include line blindly (could be intentional).
  # Leaving include line is safe; it just won't include anything if directory is empty.
  warn "No /etc/nftables.conf.bak found; leaving include line as-is (safe)."
fi

# Reload nftables safely
systemctl reload nftables 2>/dev/null || systemctl restart nftables 2>/dev/null || true

# -------- 5) suricata cleanup (SOAR-only files) --------
msg "Cleaning Suricata SOAR artifacts (if present)"
# Only remove SOAR-specific files; do not touch user's main suricata.yaml.
rm -f /etc/suricata/rules/soar.rules 2>/dev/null || true
rm -f /etc/suricata/rules/soar-agent.rules 2>/dev/null || true

# If you installed something like /etc/suricata/rules/local.soar.rules, add it here:
rm -f /etc/suricata/rules/local.soar.rules 2>/dev/null || true

# Restart Suricata if it exists
systemctl restart suricata 2>/dev/null || true

# -------- 6) remove SOAR config + data --------
msg "Removing SOAR config and data directories"
rm -rf /etc/soar
rm -rf /var/lib/soar

# -------- 7) uninstall python package --------
if [[ -n "$VENV_BIN" && -x "$VENV_BIN/pip" ]]; then
  msg "Uninstalling python package from detected venv"
  "$VENV_BIN/pip" uninstall -y soar-agent 2>/dev/null || true
else
  warn "No venv pip detected; skipping pip uninstall."
fi

# -------- 8) remove install dir --------
# IMPORTANT: only delete if it looks like a SOAR install dir
# (has agent/pyproject.toml and venv/ inside)
if [[ -d "$INSTALL_DIR" ]]; then
  if [[ -f "$INSTALL_DIR/agent/pyproject.toml" && -d "$INSTALL_DIR/venv" ]]; then
    msg "Removing install dir: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
  else
    warn "Not removing $INSTALL_DIR (does not look like a SOAR install dir)."
  fi
fi

msg "Done. Machine should be back to pre-SOAR state (SOAR-only artifacts removed)."
echo "[OK] Uninstalled."
