#!/usr/bin/env bash
# netwatch/install.sh — install all dependencies for the netwatch stack
# Run once as a sudoer: ./install.sh

set -euo pipefail

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# ── APT packages ─────────────────────────────────────────────────────────────
APT_PKGS=(
    nmap            # TCP/UDP port scan + OS/service detection
    arp-scan        # fast ARP-based LAN discovery
    fping           # parallel ICMP sweep
    masscan         # high-speed port scanner
    netdiscover     # passive/active ARP discovery
    snmp            # snmpwalk / snmpget for device enumeration
    smbclient       # SMB/CIFS share enumeration
    sshpass         # non-interactive SSH password (accessor fallback)
    python3-paramiko    # SSH in Python (netwatch + Collector)
    python3-scapy       # raw-packet sniffing / ARP
    python3-cryptography # Fernet vault encryption
)

log "Updating apt cache..."
sudo apt-get update -qq

log "Installing: ${APT_PKGS[*]}"
sudo apt-get install -y "${APT_PKGS[@]}"

# ── Python packages (pip, user-level) ────────────────────────────────────────
# paramiko via apt above covers netwatch + Collector; add extras here if needed
#PIP_PKGS=(requests)
#log "Installing Python packages: ${PIP_PKGS[*]}"
#pip3 install --quiet --user "${PIP_PKGS[@]}"

# ── Runtime directories ───────────────────────────────────────────────────────
NWDIR="$HOME/.netwatch"
mkdir -p "$NWDIR/logs"
chmod 700 "$NWDIR"

log "Created $NWDIR"

# ── Cron entry (every 5 minutes) ─────────────────────────────────────────────
CRON_CMD="*/5 * * * * /usr/bin/python3 $HOME/netwatch/netwatch.py --once >> $NWDIR/logs/cron.log 2>&1"
# Only add if not already present
if crontab -l 2>/dev/null | grep -qF "netwatch.py"; then
    log "Cron entry already present — skipping."
else
    (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
    log "Cron entry added: $CRON_CMD"
fi

log "Installation complete."
log "Next: run  python3 ~/netwatch/netwatch.py --add-cred  to populate the vault."
