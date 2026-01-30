#!/bin/bash
# -------------------------------------------------------------------------
# Ubuntu Optimizer
# Author: aeTunga
# Repository: https://github.com/aeTunga/ubuntu-optimizer
# -------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/ubuntu-optimizer.log"
PRE_FLIGHT_LOG="$SCRIPT_DIR/ubuntu-optimizer.preflight.log"
POST_FLIGHT_LOG="$SCRIPT_DIR/ubuntu-optimizer.postflight.log"

log() { echo "[INFO] $1" | tee -a "$LOG_FILE"; }
warn() { echo "[WARN] $1" | tee -a "$LOG_FILE"; }
error() { echo "[ERROR] $1" | tee -a "$LOG_FILE"; }

backup_file() {
    local path="$1"
    if [ -e "$path" ] && [ ! -e "${path}.bak" ]; then
        cp -a "$path" "${path}.bak" || warn "Failed to back up $path"
    fi
}

ask_yes_no() {
    local prompt="$1"
    local reply
    read -r -p "$prompt" reply
    case "$reply" in
        yes|y|Y|YES) return 0 ;;
        *) return 1 ;;
    esac
}

snapshot_state() {
    echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p)"
    echo ""
    if command -v ss >/dev/null 2>&1; then
        echo "[Network sockets]"
        ss -tupn
        echo ""
    fi
    echo "[Top network connections]"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -i
    else
        echo "lsof not found"
    fi
    echo ""
    echo "[Disk usage]"
    df -h
    echo ""
    echo "[Memory usage]"
    free -h
    echo ""
    echo "[Top disk I/O processes]"
    if command -v iotop >/dev/null 2>&1; then
        iotop -b -o -n 1
    else
        echo "iotop not found"
    fi
    echo ""
    echo "[Top CPU processes]"
    ps aux --sort=-%cpu
    echo ""
    echo "[Top memory processes]"
    ps aux --sort=-%mem
}

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

echo "--- PRE-FLIGHT: TOOLING ---"
if ! command -v lsof >/dev/null 2>&1 || ! command -v iotop >/dev/null 2>&1; then
    apt-get update -qq || warn "apt-get update failed; pre-flight tooling may be incomplete"
fi
if ! command -v lsof >/dev/null 2>&1; then
    apt-get install -y lsof >/dev/null 2>&1 && log "Installed lsof" || warn "Failed to install lsof"
fi
if ! command -v iotop >/dev/null 2>&1; then
    apt-get install -y iotop >/dev/null 2>&1 && log "Installed iotop" || warn "Failed to install iotop"
fi

echo "--- PRE-FLIGHT: IPROUTE2 CHECK ---"
if command -v ss >/dev/null 2>&1; then
    log "ss found at $(command -v ss)"
else
    warn "ss not found"
fi
if command -v dpkg >/dev/null 2>&1; then
    dpkg -l iproute2 2>/dev/null | tee -a "$LOG_FILE"
fi
if command -v apt-cache >/dev/null 2>&1; then
    apt-cache policy iproute2 2>/dev/null | tee -a "$LOG_FILE"
fi

echo "--- [0/7] PRE-FLIGHT SNAPSHOT (NETWORK/DISK/PROCESSES) ---"
snapshot_state | tee "$PRE_FLIGHT_LOG"
log "Pre-flight snapshot saved to $PRE_FLIGHT_LOG"

echo "--- [1/7] NETWORK ENHANCEMENT: TCP BBR ---"
backup_file /etc/sysctl.d/99-performance.conf
grep -qxF 'net.core.default_qdisc=fq' /etc/sysctl.d/99-performance.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/99-performance.conf
grep -qxF 'net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.d/99-performance.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-performance.conf
log "TCP BBR settings applied"

echo "--- [2/7] SSH FAST-LOGIN & HARDENING ---"
# Disables DNS lookups and GSSAPI for near-instant SSH connection
backup_file /etc/ssh/sshd_config
if grep -qE '^[#[:space:]]*UseDNS\b' /etc/ssh/sshd_config; then
    sed -i -E 's/^[#[:space:]]*UseDNS\b.*/UseDNS no/' /etc/ssh/sshd_config
else
    echo 'UseDNS no' >> /etc/ssh/sshd_config
fi
if grep -qE '^[#[:space:]]*GSSAPIAuthentication\b' /etc/ssh/sshd_config; then
    sed -i -E 's/^[#[:space:]]*GSSAPIAuthentication\b.*/GSSAPIAuthentication no/' /etc/ssh/sshd_config
else
    echo 'GSSAPIAuthentication no' >> /etc/ssh/sshd_config
fi
systemctl restart ssh || { error "Failed to restart ssh"; }
log "SSH config hardened"

echo "--- [3/7] INCREASING SYSTEM LIMITS (Ulimit) ---"
# Essential for high-concurrency apps (Rust/C++/Database)
if ! grep -q '^\* soft nofile 1048576' /etc/security/limits.conf; then
    echo '* soft nofile 1048576' >> /etc/security/limits.conf
fi
if ! grep -q '^\* hard nofile 1048576' /etc/security/limits.conf; then
    echo '* hard nofile 1048576' >> /etc/security/limits.conf
fi
if ! grep -q '^root soft nofile 1048576' /etc/security/limits.conf; then
    echo 'root soft nofile 1048576' >> /etc/security/limits.conf
fi
if ! grep -q '^root hard nofile 1048576' /etc/security/limits.conf; then
    echo 'root hard nofile 1048576' >> /etc/security/limits.conf
fi
log "System limits updated"

echo "--- [4/7] EXTREME KERNEL & NETWORK TUNING ---"
for line in \
    '# RAM & Memory Management' \
    'vm.swappiness=0' \
    'vm.vfs_cache_pressure=50' \
    'vm.dirty_ratio=10' \
    'vm.dirty_background_ratio=5' \
    '' \
    '# High-Concurrency Network Stack' \
    'net.core.somaxconn=65535' \
    'net.core.netdev_max_backlog=5000' \
    'net.ipv4.tcp_fastopen=3' \
    'net.ipv4.tcp_fin_timeout=15' \
    'net.ipv4.tcp_tw_reuse=1' \
    'net.ipv4.tcp_max_syn_backlog=8192' \
    'net.ipv4.tcp_slow_start_after_idle=0' \
    'net.ipv4.ip_local_port_range=1024 65535' \
    '' \
    '# File System Limits' \
    'fs.file-max=2097152'
do
    grep -qxF "$line" /etc/sysctl.d/99-performance.conf || echo "$line" >> /etc/sysctl.d/99-performance.conf
done
sysctl --system || { error "sysctl reload failed"; }
log "Kernel/network tuning applied"

echo "--- CONFIRMATION: SELECTIVE DESTRUCTIVE CHANGES ---"
echo "Replacing /etc/resolv.conf disables systemd-resolved and overrides DNS."
if ask_yes_no "Disable systemd-resolved and replace /etc/resolv.conf? (yes/NO): "; then
    DO_REPLACE_RESOLVCONF=1
else
    DO_REPLACE_RESOLVCONF=0
fi

echo "--- [5/7] TOTAL PURGE: SNAP & CLOUD AGENTS ---"
oracle_units=$(systemctl list-units --all 'snap.oracle-cloud-agent*' --no-legend 2>/dev/null | awk '{print $1}')
if [ -n "$oracle_units" ]; then
    for unit in $oracle_units; do
        systemctl stop "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
        systemctl mask "$unit" 2>/dev/null || true
    done
    log "Oracle Cloud Agent units stopped/disabled/masked"
fi
oracle_units=$(systemctl list-units --all 'oracle-cloud-agent*' --no-legend 2>/dev/null | awk '{print $1}')
if [ -n "$oracle_units" ]; then
    for unit in $oracle_units; do
        systemctl stop "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
        systemctl mask "$unit" 2>/dev/null || true
    done
    log "Oracle Cloud Agent units (non-snap) stopped/disabled/masked"
fi
if command -v snap >/dev/null 2>&1; then
    snap_list=$(snap list | awk '!/^Name|^Core/ {print $1}')
    if [ -n "$snap_list" ]; then
        snap remove --purge $snap_list 2>/dev/null || true
    else
        log "No snaps found to remove"
    fi
    systemctl stop snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    systemctl disable snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    systemctl mask snapd.service snapd.socket snapd.seeded.service 2>/dev/null || true
    umount -l /snap/* 2>/dev/null || true
else
    warn "snap is not installed; skipping snap removal"
fi
apt-get purge -y snapd squashfs-tools oracle-cloud-agent* 2>/dev/null
rm -rf /var/cache/snapd
rm -rf /var/lib/snapd
systemctl daemon-reload 2>/dev/null || true

echo "--- [6/7] PURGING BACKGROUND BLOATWARE ---"
systemctl stop rpcbind.service 2>/dev/null || true
systemctl stop ModemManager.service 2>/dev/null || true
systemctl stop udisks2.service 2>/dev/null || true
systemctl stop iscsid.service 2>/dev/null || true
systemctl stop unattended-upgrades.service 2>/dev/null || true
apt-get purge -y \
    unattended-upgrades \
    modemmanager \
    policykit-1 \
    polkitd \
    accountsservice \
    udisks2 \
    open-iscsi \
    iscsid \
    rpcbind \
    ubuntu-advantage-tools 2>/dev/null
echo "--- [7/7] GHOST MODE: DNS, LOGGING & CONSOLE REDUCTION ---"
if [ "$DO_REPLACE_RESOLVCONF" = "1" ]; then
    {
        echo "[DNS snapshot before change]"
        if [ -f /etc/resolv.conf ]; then
            echo "--- /etc/resolv.conf (before) ---"
            cat /etc/resolv.conf
        else
            echo "--- /etc/resolv.conf (missing) ---"
        fi
        if command -v resolvectl >/dev/null 2>&1; then
            echo "--- resolvectl status (before) ---"
            resolvectl status
        else
            echo "resolvectl not found"
        fi
        echo ""
    } | tee -a "$LOG_FILE"
    systemctl stop systemd-resolved && systemctl disable systemd-resolved && systemctl mask systemd-resolved
    backup_file /etc/resolv.conf
    if [ -e /etc/resolv.conf ]; then
        rm -f /etc/resolv.conf
    fi
    printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf
    chmod 644 /etc/resolv.conf
    log "DNS set to Cloudflare/Google"
else
    log "DNS handling unchanged"
fi

journalctl --vacuum-time=1s
backup_file /etc/systemd/journald.conf
if grep -qE '^[#[:space:]]*Storage=' /etc/systemd/journald.conf; then
    sed -i -E 's/^[#[:space:]]*Storage=.*/Storage=volatile/' /etc/systemd/journald.conf
else
    echo 'Storage=volatile' >> /etc/systemd/journald.conf
fi
if grep -qE '^[#[:space:]]*SystemMaxUse=' /etc/systemd/journald.conf; then
    sed -i -E 's/^[#[:space:]]*SystemMaxUse=.*/SystemMaxUse=50M/' /etc/systemd/journald.conf
else
    echo 'SystemMaxUse=50M' >> /etc/systemd/journald.conf
fi

systemctl restart systemd-journald || { error "Failed to restart journald"; }
log "Logging and console reduced"

# Final deep clean
apt-get autoremove --purge -y && apt-get clean
rm -rf /usr/share/doc/* /usr/share/man/*
rm -rf /var/lib/apt/lists/*

echo "--- WAIT: FWUPD QUIET ---"
if systemctl is-active --quiet fwupd 2>/dev/null; then
    log "fwupd active; waiting for completion"
    wait_seconds=120
    while systemctl is-active --quiet fwupd 2>/dev/null && [ $wait_seconds -gt 0 ]; do
        sleep 5
        wait_seconds=$((wait_seconds - 5))
    done
    if systemctl is-active --quiet fwupd 2>/dev/null; then
        warn "fwupd still active after wait; continuing"
    else
        log "fwupd inactive; continuing"
    fi
fi

if ! command -v ss >/dev/null 2>&1; then
    apt-get update -qq || warn "apt-get update failed; ss may remain unavailable"
    apt-get install -y iproute2 >/dev/null 2>&1 && log "Installed iproute2 for post-flight" || warn "Failed to install iproute2"
fi

echo "--- [POST] SNAPSHOT (NETWORK/DISK/PROCESSES) ---"
snapshot_state | tee "$POST_FLIGHT_LOG"
log "Post-flight snapshot saved to $POST_FLIGHT_LOG"

echo "--- OPTIMIZATION COMPLETE: REBOOT RECOMMENDED ---"
