#!/usr/bin/env bash
set -euo pipefail

SOAR_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOAR_DST_DIR="/opt/soar"
VENV_DIR="$SOAR_DST_DIR/venv"
CFG_DIR="/etc/soar"
CFG_FILE="$CFG_DIR/soar.yaml"
SERVICE_FILE="/etc/systemd/system/soar-engine.service"

echo "[*] Installing SOAR into $SOAR_DST_DIR"

# --- must be root ---
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./install.sh"
  exit 1
fi

# --- deps ---
echo "[*] Installing dependencies (python3-venv, nftables, rsync)"
apt-get update -y
apt-get install -y python3 python3-venv python3-pip nftables rsync

# --- copy repo to /opt/soar ---
echo "[*] Syncing files to $SOAR_DST_DIR"
mkdir -p "$SOAR_DST_DIR"
rsync -a --delete \
  --exclude 'venv/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '*.db' \
  "$SOAR_SRC_DIR/" "$SOAR_DST_DIR/"

# --- venv ---
echo "[*] Creating venv at $VENV_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install -U pip setuptools wheel

# --- install package (editable for now) ---
echo "[*] Installing soar-agent package"
"$VENV_DIR/bin/pip" install -e "$SOAR_DST_DIR/agent"

# --- config ---
echo "[*] Installing config to $CFG_FILE (if missing)"
mkdir -p "$CFG_DIR"
if [[ ! -f "$CFG_FILE" ]]; then
  if [[ -f "$SOAR_DST_DIR/agent/config.yaml" ]]; then
    cp -f "$SOAR_DST_DIR/agent/config.yaml" "$CFG_FILE"
  else
    echo "ERROR: missing $SOAR_DST_DIR/agent/config.yaml"
    exit 1
  fi
fi
chmod 644 "$CFG_FILE"

# --- ensure db dir ---
mkdir -p /var/lib/soar
chmod 755 /var/lib/soar

# --- nftables init ---
echo "[*] Running soarctl init"
SOAR_CONFIG_PATH="$CFG_FILE" "$VENV_DIR/bin/soarctl" init

# --- systemd unit (foreground) ---
echo "[*] Installing systemd service: soar-engine.service"
cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=SOAR Decision Engine
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=simple
Environment=SOAR_CONFIG_PATH=$CFG_FILE
ExecStart=$VENV_DIR/bin/soarctl engine start
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now soar-engine.service

# --- global CLI ---
echo "[*] Installing /usr/local/bin/soarctl"
ln -sf "$VENV_DIR/bin/soarctl" /usr/local/bin/soarctl

echo
echo "[OK] Installed."
echo "    - CLI:   soarctl version"
echo "    - Init:  sudo soarctl init"
echo "    - Svc:   sudo systemctl status soar-engine.service"
