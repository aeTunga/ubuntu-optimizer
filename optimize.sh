#!/bin/bash
# -------------------------------------------------------------------------
# Ubuntu Optimizer
# Author: aeTunga
# Repository: https://github.com/aeTunga/ubuntu-optimizer
#
# Safety model:
#   - never restarts sshd without `sshd -t` validation + rollback
#   - never purges packages without inspecting apt's removal plan
#   - never touches iSCSI stack while iSCSI sessions/devices exist
#   - never leaves an /etc/fstab that fails `findmnt --verify`
#   - never disables cloud-init before it reports 'done'
#   - all destructive DNS work is opt-in and non-interactive-safe
#
# Env overrides (for unattended runs):
#   OPTIMIZER_REPLACE_RESOLVCONF=0|1   default 0 (skip)
#   OPTIMIZER_LOG_DIR=<path>           default /var/log/ubuntu-optimizer
# -------------------------------------------------------------------------

set -uo pipefail
export DEBIAN_FRONTEND=noninteractive

NOFILE_LIMIT=1048576
SYSCTL_FILE=/etc/sysctl.d/99-performance.conf
SSHD_DROPIN=/etc/ssh/sshd_config.d/99-optimizer.conf
LIMITS_FILE=/etc/security/limits.d/99-optimizer.conf
JOURNALD_DROPIN=/etc/systemd/journald.conf.d/99-optimizer.conf
ZRAM_CONF=/etc/systemd/zram-generator.conf
THP_TMPFILES=/etc/tmpfiles.d/99-optimizer-thp.conf
RPS_UNIT=/etc/systemd/system/optimizer-rps.service
# vm.swappiness is decided at runtime: 1 without swap, 100 once zram swap is up
# (compressed RAM is cheap to page to, so discouraging it wastes the device).
SWAPPINESS=1
FAILURES=0

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

LOG_DIR="${OPTIMIZER_LOG_DIR:-/var/log/ubuntu-optimizer}"
mkdir -p "$LOG_DIR" || { echo "Error: cannot create $LOG_DIR" >&2; exit 1; }
RUN_ID="$(date -u '+%Y%m%dT%H%M%SZ')"
LOG_FILE="$LOG_DIR/run-$RUN_ID.log"
PRE_FLIGHT_LOG="$LOG_DIR/preflight-$RUN_ID.log"
POST_FLIGHT_LOG="$LOG_DIR/postflight-$RUN_ID.log"

# Capture EVERYTHING (apt, systemctl, sed, snap) into the run log, not just our
# own log lines.
exec > >(tee -a "$LOG_FILE") 2>&1
TEE_PID=$!
ln -sfn "$LOG_FILE" "$LOG_DIR/latest.log" 2>/dev/null || true

# ---------------------------------------------------------------- primitives

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { printf '[%s] [INFO] %s\n' "$(ts)" "$1"; }
warn() { printf '[%s] [WARN] %s\n' "$(ts)" "$1" >&2; }
error() { printf '[%s] [ERROR] %s\n' "$(ts)" "$1" >&2; FAILURES=$((FAILURES + 1)); }
section() { printf '\n--- %s ---\n' "$1"; }

backup_file() {
    local path="$1"
    [ -e "$path" ] || return 0
    [ -e "${path}.bak" ] && return 0
    # -L dereferences symlinks (/etc/resolv.conf is one): a symlink copy would
    # dangle after systemd-resolved is masked, making rollback useless.
    cp -aL "$path" "${path}.bak" 2>/dev/null ||
        cp -a "$path" "${path}.bak" ||
        warn "Failed to back up $path"
}

ask_yes_no() {
    local prompt="$1" reply=""
    # Under `curl | bash` stdin is the script itself; reading it would eat the
    # remaining script body. Always read the terminal, never fd 0.
    if [ -r /dev/tty ]; then
        read -r -p "$prompt" reply </dev/tty || reply=""
    else
        echo "$prompt [no tty -> NO]"
        return 1
    fi
    case "${reply,,}" in
        yes | y) return 0 ;;
        *) return 1 ;;
    esac
}

write_if_changed() {
    # write_if_changed <path> <<<content ; idempotent, backs up foreign content
    local path="$1" tmp
    tmp="$(mktemp)"
    cat >"$tmp"
    if [ -e "$path" ] && cmp -s "$tmp" "$path"; then
        rm -f "$tmp"
        log "Unchanged: $path"
        return 0
    fi
    backup_file "$path"
    mkdir -p "$(dirname "$path")"
    cat "$tmp" >"$path"
    rm -f "$tmp"
    chmod 644 "$path"
    log "Wrote: $path"
}

apt_wait() {
    # Acquire+release the dpkg frontend lock: waits out unattended-upgrades /
    # cloud-init without deadlocking apt itself.
    flock -w 300 /var/lib/dpkg/lock-frontend true 2>/dev/null && return 0
    error "dpkg lock still held after 300s"
    return 1
}

apt_run() {
    apt_wait || return 1
    apt-get "$@"
}

ensure_apt_lists() {
    # Package lists are wiped in the cleanup phase; refresh them on demand
    # instead of failing an install later in the run.
    compgen -G '/var/lib/apt/lists/*Packages*' >/dev/null 2>&1 && return 0
    apt_run update -qq || {
        warn "apt-get update failed; package installs may fail"
        return 1
    }
}

apt_install() {
    local pkg="$1"
    # Exact match: dpkg-query prints "not-installed" for known-but-absent
    # packages, which a substring test would read as installed.
    [ "$(dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null)" = "installed" ] && return 0
    ensure_apt_lists
    apt_run install -y --no-install-recommends "$pkg" >/dev/null 2>&1 && {
        log "Installed $pkg"
        return 0
    }
    warn "Failed to install $pkg"
    return 1
}

unit_exists() {
    systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q .
}

kill_units() {
    local unit
    for unit in "$@"; do
        unit_exists "$unit" || continue
        systemctl stop "$unit" 2>/dev/null
        systemctl disable "$unit" 2>/dev/null
        systemctl mask "$unit" 2>/dev/null
        log "Stopped/disabled/masked $unit"
    done
}

resolve_installed() {
    # Expand package patterns to actually-installed package names. Needed because
    # `apt-get purge` aborts on unknown names, which would void the whole batch.
    local pat name status out=()
    for pat in "$@"; do
        while read -r name status; do
            [ "$status" = installed ] && out+=("$name")
        done < <(dpkg-query -W -f='${binary:Package} ${db:Status-Status}\n' "$pat" 2>/dev/null)
    done
    [ ${#out[@]} -gt 0 ] && printf '%s\n' "${out[@]}"
}

ssh_config_valid() {
    # `sshd -t` also fails on environment problems (missing /run/sshd privsep
    # dir when the unit never started, missing host keys). Those must not
    # trigger a config rollback, so create the privsep dir first and only treat
    # errors that name a config file as real config errors.
    local out rc
    mkdir -p /run/sshd 2>/dev/null && chmod 0755 /run/sshd 2>/dev/null
    out="$("${SSHD_BIN:-/usr/sbin/sshd}" -t 2>&1)"
    rc=$?
    [ $rc -eq 0 ] && return 0
    printf '%s\n' "$out" >&2
    if ! printf '%s' "$out" | grep -q '/etc/ssh/'; then
        warn "sshd -t failed for environment reasons, not configuration; keeping changes"
        return 0
    fi
    return 1
}

PROTECTED_RE='^(systemd|systemd-sysv|systemd-timesyncd|udev|libc6|bash|coreutils|dpkg|apt|sudo|openssh-server|openssh-client|cloud-init|netplan\.io|linux-image|linux-generic|linux-modules|grub|ubuntu-server|ubuntu-minimal|util-linux|iproute2)'

safe_purge() {
    # Inspect apt's real removal plan before committing: `purge -y` silently
    # drags in reverse dependencies.
    local pkgs=("$@") sim plan rc
    [ ${#pkgs[@]} -eq 0 ] && return 0
    apt_wait || return 1
    sim="$(apt-get -s purge -y "${pkgs[@]}" 2>&1)"
    rc=$?
    # apt marks purges as "Purg" and dependency-only removals as "Remv":
    # matching only one of them would hide half the plan.
    plan="$(printf '%s\n' "$sim" | awk '/^(Remv|Purg)/ {print $2}')"
    if [ "$rc" -ne 0 ]; then
        # apt refused to even plan this (broken deps / essential package):
        # skipping is the safe direction, but say so instead of claiming "empty".
        warn "apt refused to plan purge of ${pkgs[*]} (rc=$rc); skipping"
        printf '%s\n' "$sim" | grep -E '^(E:|W:|The following)' | head -5 >&2
        return 1
    fi
    if [ -z "$plan" ]; then
        log "Purge plan empty for: ${pkgs[*]}"
        return 0
    fi
    log "Purge plan: $(echo "$plan" | tr '\n' ' ')"
    if echo "$plan" | grep -qE "$PROTECTED_RE"; then
        warn "Refusing purge of ${pkgs[*]}: plan touches protected packages ($(echo "$plan" | tr '\n' ' '))"
        return 1
    fi
    apt_run purge -y "${pkgs[@]}" || error "Purge failed: ${pkgs[*]}"
}

purge_patterns() {
    # One apt call per package: batching means a single package with protected
    # collateral (e.g. ubuntu-pro-client -> ubuntu-minimal) blocks the whole
    # batch and nothing gets cleaned.
    local pkgs=() p
    mapfile -t pkgs < <(resolve_installed "$@")
    if [ ${#pkgs[@]} -eq 0 ]; then
        log "Not installed, nothing to purge: $*"
        return 0
    fi
    for p in "${pkgs[@]}"; do
        safe_purge "$p"
    done
}

safe_autoremove() {
    # autoremove inherits whatever the purges orphaned; inspect it with the same
    # discipline instead of trusting -y.
    local sim plan rc
    apt_wait || return 1
    sim="$(apt-get -s autoremove --purge -y 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        warn "apt refused to plan autoremove (rc=$rc); skipping"
        return 1
    fi
    plan="$(printf '%s\n' "$sim" | awk '/^(Remv|Purg)/ {print $2}')"
    if [ -z "$plan" ]; then
        log "Nothing to autoremove"
        return 0
    fi
    log "Autoremove plan: $(echo "$plan" | tr '\n' ' ')"
    if echo "$plan" | grep -qE "$PROTECTED_RE"; then
        warn "Skipping autoremove: plan touches protected packages"
        return 1
    fi
    apt_run autoremove --purge -y || warn "autoremove failed"
}

check_sysctl() {
    local key="$1" want="$2" got
    got="$(sysctl -n "$key" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/ $//')"
    if [ "$got" = "$want" ]; then
        log "verify OK   $key = $got"
    else
        warn "verify FAIL $key: want '$want', got '${got:-<unset>}'"
    fi
}

is_oci() {
    grep -qi oraclecloud /sys/devices/virtual/dmi/id/chassis_asset_tag 2>/dev/null
}

iscsi_in_use() {
    if command -v iscsiadm >/dev/null 2>&1 && iscsiadm -m session >/dev/null 2>&1; then
        return 0
    fi
    compgen -G '/dev/disk/by-path/*iscsi*' >/dev/null 2>&1
}

snapshot_state() {
    echo "Timestamp: $(ts)"
    echo "Hostname: $(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo ""
    if command -v ss >/dev/null 2>&1; then
        echo "[Network sockets]"
        ss -tupn 2>&1
        echo ""
    fi
    echo "[Open network files]"
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -i 2>&1
    else
        echo "lsof not found"
    fi
    echo ""
    echo "[Disk usage]"
    df -h 2>&1
    echo ""
    echo "[Memory usage]"
    free -h 2>&1
    echo ""
    echo "[Top disk I/O processes]"
    if command -v iotop >/dev/null 2>&1; then
        # Fails without kernel delay accounting (needs delayacct=1 since 5.14).
        iotop -b -o -n 1 2>&1 | head -20
    else
        echo "iotop not found"
    fi
    echo ""
    echo "[Top CPU processes]"
    ps aux --sort=-%cpu 2>&1 | head -20
    echo ""
    echo "[Top memory processes]"
    ps aux --sort=-%mem 2>&1 | head -20
    echo ""
    echo "[Failed units]"
    systemctl list-units --failed --no-legend 2>&1 || true
}

# ------------------------------------------------------------ environment guard

section "PRE-FLIGHT: ENVIRONMENT"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
fi
case "${ID:-unknown}" in
    ubuntu) log "Distro: ${PRETTY_NAME:-Ubuntu}" ;;
    debian) warn "Debian detected; package names differ, continuing best-effort" ;;
    *)
        error "Unsupported distro '${ID:-unknown}'; aborting"
        exit 1
        ;;
esac

if [ ! -d /run/systemd/system ]; then
    error "systemd not running (container without systemd?); aborting"
    exit 1
fi

IS_CONTAINER=0
if systemd-detect-virt -c >/dev/null 2>&1; then
    IS_CONTAINER=1
    warn "Container detected ($(systemd-detect-virt -c)): host-wide kernel keys cannot be set here, tuning is best-effort"
fi
IS_OCI=0
is_oci && { IS_OCI=1; log "Oracle Cloud Infrastructure detected"; }

# ------------------------------------------------------------ decisions upfront

section "CONFIRMATION: SELECTIVE DESTRUCTIVE CHANGES"
DO_REPLACE_RESOLVCONF="${OPTIMIZER_REPLACE_RESOLVCONF:-}"
if [ -z "$DO_REPLACE_RESOLVCONF" ]; then
    echo "Replacing /etc/resolv.conf disables systemd-resolved and overrides DNS."
    [ "$IS_OCI" = 1 ] && echo "NOTE: on OCI this can break *.oraclevcn.com and metadata resolution."
    if ask_yes_no "Disable systemd-resolved and replace /etc/resolv.conf? (yes/NO): "; then
        DO_REPLACE_RESOLVCONF=1
    else
        DO_REPLACE_RESOLVCONF=0
    fi
fi
log "Replace resolv.conf: $DO_REPLACE_RESOLVCONF"

KEEP_ISCSI=0
if iscsi_in_use; then
    KEEP_ISCSI=1
    warn "Active iSCSI sessions/devices found: open-iscsi/iscsid will be KEPT (removing them can make attached volumes unavailable after reboot)"
elif [ "$IS_OCI" = 1 ]; then
    KEEP_ISCSI=1
    warn "OCI without visible iSCSI sessions: keeping open-iscsi anyway (block volume attachments rely on it)"
fi

# ------------------------------------------------------------ pre-flight tools

section "PRE-FLIGHT: TOOLING"
if ! command -v lsof >/dev/null 2>&1 || ! command -v iotop >/dev/null 2>&1; then
    apt_run update -qq || warn "apt-get update failed; pre-flight tooling may be incomplete"
fi
for tool in lsof iotop; do
    apt_install "$tool"
done
if command -v ss >/dev/null 2>&1; then
    log "ss found at $(command -v ss)"
else
    warn "ss not found (iproute2 missing?)"
fi

section "[0/9] PRE-FLIGHT SNAPSHOT (NETWORK/DISK/PROCESSES)"
snapshot_state >"$PRE_FLIGHT_LOG" 2>&1
log "Pre-flight snapshot saved to $PRE_FLIGHT_LOG"

# ---------------------------------------------------------------------- memory

section "[1/9] MEMORY: ZRAM SWAP"
# A small instance with no swap and swappiness=1 has nowhere to go under memory
# pressure except the OOM killer. zram gives compressed in-RAM swap (~2-3x
# effective capacity) with zero disk I/O.
if [ "$IS_CONTAINER" = 1 ]; then
    warn "Container: zram needs host kernel access; skipping"
elif ! modprobe zram 2>/dev/null &&
    ! { apt_install "linux-modules-extra-$(uname -r)" && modprobe zram 2>/dev/null; }; then
    # Ubuntu ships the zram module in linux-modules-extra-*, which cloud images
    # do not always install. No module -> no zram, and swappiness stays low.
    warn "zram kernel module unavailable (linux-modules-extra missing?); keeping swappiness=$SWAPPINESS"
elif apt_install systemd-zram-generator; then
    write_if_changed "$ZRAM_CONF" <<'EOF'
# Managed by ubuntu-optimizer.
[zram0]
zram-size = min(ram, 4096)
compression-algorithm = zstd
swap-priority = 100
fs-type = swap
EOF
    # daemon-reload re-runs the generator so systemd-zram-setup@zram0 exists.
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart systemd-zram-setup@zram0.service 2>/dev/null ||
        warn "systemd-zram-setup@zram0 failed to start"
    # The device is created by the setup service, but swapon happens in the
    # generated dev-zram0.swap unit - starting only the former returns before
    # any swap exists.
    systemctl start dev-zram0.swap 2>/dev/null || true
    zram_wait=10
    while [ "$zram_wait" -gt 0 ] && ! swapon --show=NAME --noheadings 2>/dev/null | grep -q zram; do
        sleep 1
        zram_wait=$((zram_wait - 1))
    done
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q zram; then
        # Cheap swap device -> let the kernel actually use it, and disable
        # readahead (page-cluster=0) because zram has no seek penalty.
        SWAPPINESS=100
        log "zram swap active: $(swapon --show=NAME,SIZE,PRIO --noheadings | tr '\n' ' ')"
    else
        warn "zram device did not come up; keeping swappiness=$SWAPPINESS"
    fi
else
    warn "systemd-zram-generator unavailable; keeping swappiness=$SWAPPINESS"
fi

# ------------------------------------------------------------ kernel / network

section "[2/9] KERNEL, NETWORK & TCP BBR TUNING"
# Managed file: rewritten wholesale so repeated runs cannot accumulate
# duplicate or conflicting keys.
write_if_changed "$SYSCTL_FILE" <<EOF
# Managed by ubuntu-optimizer. Manual edits are overwritten.

# Congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# RAM & memory management
# swappiness: 100 with zram (compressed RAM swap is cheap), 1 without swap.
# Never 0 - that disables anonymous reclaim and invites the OOM killer.
vm.swappiness=$SWAPPINESS
vm.page-cluster=0
vm.vfs_cache_pressure=50
vm.dirty_ratio=10
vm.dirty_background_ratio=5

# High-concurrency network stack
net.core.somaxconn=65535
net.core.netdev_max_backlog=5000
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_slow_start_after_idle=0
# Ephemeral range starts at 10240 so outbound sockets cannot squat on service
# ports (3306/5432/6379/8080...) and break a service restart.
net.ipv4.ip_local_port_range=10240 65535

# Socket buffers sized for long fat pipes: BBR cannot fill a 1Gbps x 150ms path
# (~18MB BDP) through the default 6MB ceiling.
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 131072 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
# Survive PMTU blackholes instead of stalling mid-transfer.
net.ipv4.tcp_mtu_probing=1
# Receive packet steering budget (per-flow table); the per-queue mask is set by
# optimizer-rps.service below.
net.core.rps_sock_flow_entries=32768

# File system limits
fs.file-max=2097152
fs.nr_open=$NOFILE_LIMIT

# Console verbosity (KERN_ERR to console, full detail to journal)
kernel.printk=3 4 1 3
EOF

modprobe tcp_bbr 2>/dev/null || true
modprobe sch_fq 2>/dev/null || true
if sysctl --system >/dev/null 2>&1; then
    log "Kernel/network tuning applied"
elif [ "$IS_CONTAINER" = 1 ]; then
    # Namespaced keys still apply; host-only keys (net.core.*, congestion
    # control) are invisible in a container and simply cannot be set here.
    warn "Some sysctl keys are not settable in a container; applied what was possible"
else
    error "sysctl reload failed"
    sysctl --system 2>&1 | grep -E '^sysctl:' | head -5 >&2
fi

# Transparent hugepages: "always" causes allocation stalls and latency spikes in
# databases/caches; "madvise" keeps the benefit only where an app asks for it.
write_if_changed "$THP_TMPFILES" <<'EOF'
# Managed by ubuntu-optimizer.
w- /sys/kernel/mm/transparent_hugepage/enabled - - - - madvise
w- /sys/kernel/mm/transparent_hugepage/defrag - - - - defer+madvise
EOF
systemd-tmpfiles --create "$THP_TMPFILES" 2>/dev/null ||
    warn "Could not apply THP setting now (applies on next boot)"

# Receive Packet Steering: single-queue virtio NICs process all softirqs on one
# CPU. Spreading them costs nothing and lifts the packet-rate ceiling on
# multi-vCPU guests.
CPU_COUNT="$(nproc 2>/dev/null || echo 1)"
if [ "$CPU_COUNT" -gt 1 ]; then
    # The logic lives in a script, not in ExecStart: systemd expands $VAR itself,
    # so an inline shell one-liner would receive empty variables.
    write_if_changed /usr/local/sbin/optimizer-rps <<'EOF'
#!/bin/bash
# Managed by ubuntu-optimizer: spread NIC receive softirqs across all CPUs.
set -u
cpus="$(nproc)"
mask="$(printf '%x' $(((1 << cpus) - 1)))"
applied=0
for q in /sys/class/net/*/queues/rx-*/rps_cpus; do
    case "$q" in */lo/*) continue ;; esac
    [ -w "$q" ] || continue
    echo "$mask" >"$q" 2>/dev/null && applied=$((applied + 1))
done
echo "rps_cpus=$mask applied to $applied queue(s)"
EOF
    chmod 755 /usr/local/sbin/optimizer-rps
    write_if_changed "$RPS_UNIT" <<'EOF'
# Managed by ubuntu-optimizer.
[Unit]
Description=Spread NIC receive processing across CPUs (RPS)
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/optimizer-rps

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload 2>/dev/null || true
    if systemctl enable --now optimizer-rps.service 2>/dev/null; then
        log "RPS enabled across $CPU_COUNT CPUs: $(/usr/local/sbin/optimizer-rps)"
    else
        warn "Failed to enable optimizer-rps.service"
    fi
else
    log "Single vCPU: RPS not useful, skipped"
fi

# ------------------------------------------------------------------------- ssh

section "[3/9] SSH FAST-LOGIN & HARDENING"
# Disables DNS lookups and GSSAPI for near-instant SSH connection.
if ! command -v sshd >/dev/null 2>&1 && [ ! -x /usr/sbin/sshd ]; then
    warn "sshd not installed; skipping SSH section"
else
    SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
    if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
        # Include sits at the top of Ubuntu's sshd_config and sshd keeps the
        # FIRST value it sees, so a drop-in actually wins. Appending to the main
        # file does not.
        write_if_changed "$SSHD_DROPIN" <<'EOF'
# Managed by ubuntu-optimizer.
UseDNS no
GSSAPIAuthentication no
EOF
        SSH_TOUCHED="$SSHD_DROPIN"
    else
        warn "sshd_config has no drop-in Include; editing main config"
        backup_file /etc/ssh/sshd_config
        for kv in "UseDNS no" "GSSAPIAuthentication no"; do
            key="${kv%% *}"
            if grep -qE "^[#[:space:]]*${key}\b" /etc/ssh/sshd_config; then
                sed -i -E "s/^[#[:space:]]*${key}\b.*/${kv}/" /etc/ssh/sshd_config
            else
                echo "$kv" >>/etc/ssh/sshd_config
            fi
        done
        SSH_TOUCHED=/etc/ssh/sshd_config
    fi

    if ssh_config_valid; then
        SSH_UNIT=ssh.service
        unit_exists ssh.service || SSH_UNIT=sshd.service
        if [ "$(systemctl is-enabled ssh.socket 2>/dev/null)" = enabled ]; then
            # Ubuntu 22.10+ default: sshd is socket-activated and every incoming
            # connection spawns a fresh sshd that re-reads the config. Starting
            # the service by hand would change the activation model for nothing.
            systemctl is-active --quiet "$SSH_UNIT" && systemctl reload "$SSH_UNIT" 2>/dev/null
            log "SSH config applied via $SSH_TOUCHED (socket-activated; effective for new connections)"
        elif systemctl reload "$SSH_UNIT" 2>/dev/null || systemctl restart "$SSH_UNIT"; then
            log "SSH config applied via $SSH_TOUCHED ($SSH_UNIT reloaded)"
        else
            error "Failed to reload $SSH_UNIT"
        fi
    else
        # Never leave a server with a config sshd refuses to load.
        error "sshd config validation failed; rolling back $SSH_TOUCHED"
        if [ "$SSH_TOUCHED" = "$SSHD_DROPIN" ]; then
            rm -f "$SSHD_DROPIN"
        elif [ -e /etc/ssh/sshd_config.bak ]; then
            cp -a /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        fi
        if ssh_config_valid; then
            log "Rollback restored a valid sshd config"
        else
            error "sshd config still invalid after rollback - DO NOT REBOOT, fix manually"
        fi
    fi
fi

# ---------------------------------------------------------------------- limits

section "[4/9] INCREASING SYSTEM LIMITS (Ulimit)"
# pam_limits only covers login sessions, so systemd services need their own
# drop-ins - without them "high concurrency" tuning does nothing for daemons.
write_if_changed "$LIMITS_FILE" <<EOF
# Managed by ubuntu-optimizer.
*     soft nofile $NOFILE_LIMIT
*     hard nofile $NOFILE_LIMIT
root  soft nofile $NOFILE_LIMIT
root  hard nofile $NOFILE_LIMIT
EOF

# Migrate away from lines appended to limits.conf by older versions.
if grep -qE "^(\*|root) (soft|hard) nofile $NOFILE_LIMIT$" /etc/security/limits.conf 2>/dev/null; then
    backup_file /etc/security/limits.conf
    sed -i -E "/^(\*|root) (soft|hard) nofile $NOFILE_LIMIT\$/d" /etc/security/limits.conf
    log "Removed legacy limits.conf entries (now managed in $LIMITS_FILE)"
fi

for scope in system user; do
    write_if_changed "/etc/systemd/${scope}.conf.d/99-optimizer.conf" <<EOF
# Managed by ubuntu-optimizer.
[Manager]
DefaultLimitNOFILE=$NOFILE_LIMIT:$NOFILE_LIMIT
EOF
done
systemctl daemon-reexec 2>/dev/null || warn "daemon-reexec failed; service limits apply after reboot"
log "System limits updated"

# ------------------------------------------------------------------ filesystem

section "[5/9] FILESYSTEM: NOATIME & TRIM"
# atime updates turn every read into a metadata write; noatime is the cheapest
# real I/O win on cloud volumes.
ROOT_SRC="$(findmnt -no SOURCE / 2>/dev/null)"
ROOT_FSTYPE="$(findmnt -no FSTYPE / 2>/dev/null)"
if [ -z "$ROOT_SRC" ]; then
    warn "Could not determine root device; skipping noatime"
elif findmnt -no OPTIONS / | grep -qE '(^|,)noatime(,|$)'; then
    log "Root already mounted with noatime"
else
    backup_file /etc/fstab
    # Match the entry by mountpoint: cloud images use LABEL=cloudimg-rootfs or
    # PARTUUID=, so keying on device/UUID would silently skip the rewrite.
    if awk '
        /^[[:space:]]*#/ { print; next }
        $2 == "/" {
            if ($4 !~ /(^|,)noatime(,|$)/) {
                sub(/(^|,)relatime(,|$)/, ",", $4)
                $4 = $4 ",noatime"
                gsub(/,+/, ",", $4)
                sub(/^,/, "", $4)
                sub(/,$/, "", $4)
            }
            printf "%s %s %s %s %s %s\n", $1, $2, $3, $4, ($5 == "" ? "0" : $5), ($6 == "" ? "1" : $6)
            next
        }
        { print }
    ' /etc/fstab >/tmp/fstab.opt && [ -s /tmp/fstab.opt ] &&
        grep -qE '[[:space:]]/[[:space:]].*noatime' /tmp/fstab.opt; then
        cat /tmp/fstab.opt >/etc/fstab
        if findmnt --verify --verbose >/dev/null 2>&1; then
            mount -o remount,noatime / 2>/dev/null || warn "noatime written to fstab, remount deferred to reboot"
            log "Root ($ROOT_SRC, $ROOT_FSTYPE) mounted noatime"
        else
            # A malformed fstab means an unbootable box: revert immediately.
            cp -a /etc/fstab.bak /etc/fstab
            error "fstab failed findmnt --verify; reverted"
        fi
    else
        warn "Could not rewrite root entry in /etc/fstab; skipping noatime"
    fi
    rm -f /tmp/fstab.opt
fi

# Periodic TRIM beats continuous discard: no per-delete latency penalty.
if unit_exists fstrim.timer; then
    if systemctl enable --now fstrim.timer 2>/dev/null; then
        log "fstrim.timer enabled (weekly TRIM)"
    else
        warn "Could not enable fstrim.timer"
    fi
fi
if grep -qE '^[^#].*[[:space:]]/[[:space:]].*(^|,)discard(,|$)' /etc/fstab 2>/dev/null; then
    warn "Root fstab still has 'discard'; consider removing it in favour of fstrim.timer"
fi

# ------------------------------------------------------------- snap / cloud

section "[6/9] TOTAL PURGE: SNAP & CLOUD AGENTS"
mapfile -t oracle_units < <(systemctl list-units --all 'snap.oracle-cloud-agent*' 'oracle-cloud-agent*' --no-legend 2>/dev/null | awk '{print $1}')
[ ${#oracle_units[@]} -gt 0 ] && kill_units "${oracle_units[@]}"

if command -v snap >/dev/null 2>&1; then
    # Two passes: bases (core/core22/snapd) cannot be removed while apps still
    # depend on them.
    mapfile -t snap_apps < <(snap list 2>/dev/null | awk 'NR>1 && $1 !~ /^(core|core[0-9]+|bare|snapd)$/ {print $1}')
    for s in ${snap_apps[@]+"${snap_apps[@]}"}; do
        snap remove --purge "$s" || warn "Failed to remove snap $s"
    done
    mapfile -t snap_bases < <(snap list 2>/dev/null | awk 'NR>1 {print $1}')
    for s in ${snap_bases[@]+"${snap_bases[@]}"}; do
        snap remove --purge "$s" || warn "Failed to remove snap $s"
    done
    [ ${#snap_apps[@]} -eq 0 ] && [ ${#snap_bases[@]} -eq 0 ] && log "No snaps found to remove"
    kill_units snapd.service snapd.socket snapd.seeded.service snapd.apparmor.service
else
    warn "snap is not installed; skipping snap removal"
fi

# Unmount every squashfs mount by reading the mount table (a bare /snap/* glob
# silently no-ops once the dirs are gone).
while read -r mnt; do
    umount -l "$mnt" 2>/dev/null && log "Unmounted $mnt"
done < <(awk '$2 ~ /^\/(snap|var\/lib\/snapd\/snap)\// {print $2}' /proc/self/mounts | sort -r)

purge_patterns snapd squashfs-tools 'oracle-cloud-agent*'
rm -rf /var/cache/snapd /var/lib/snapd /snap /var/snap /root/snap
rm -rf /home/*/snap
systemctl daemon-reload 2>/dev/null || true

# ------------------------------------------------------------------ bloatware

section "[7/9] PURGING BACKGROUND BLOATWARE & IDLE SERVICES"
BLOAT=(unattended-upgrades modemmanager policykit-1 polkitd accountsservice
    udisks2 rpcbind fwupd)
if [ "$KEEP_ISCSI" = 0 ]; then
    BLOAT+=(open-iscsi iscsid)
else
    log "Keeping open-iscsi/iscsid (iSCSI in use or OCI host)"
fi

for unit in rpcbind.service ModemManager.service udisks2.service iscsid.service \
    unattended-upgrades.service fwupd.service; do
    unit_exists "$unit" || continue
    [ "$KEEP_ISCSI" = 1 ] && [ "$unit" = iscsid.service ] && continue
    systemctl stop "$unit" 2>/dev/null || true
done
purge_patterns "${BLOAT[@]}"

# ubuntu-pro-client is NOT purged: apt would take ubuntu-minimal with it, and the
# following autoremove could then cascade into base packages. Masking its units
# removes the background work without touching the metapackage.
kill_units ua-timer.timer ua-reboot-cmds.service ubuntu-advantage.service \
    apt-news.service esm-cache.service
purge_patterns ubuntu-advantage-tools

# Purging unattended-upgrades does not stop apt's own timers, nor fwupd's
# refresh timer: mask what is left instead of waiting for it later.
kill_units apt-daily.timer apt-daily-upgrade.timer fwupd-refresh.timer \
    motd-news.timer motd-news.service
warn "Automatic security updates are now disabled; patch this host manually"

# Base services that idle on a headless server: multipathd only matters with
# multipath storage, lxd/lxd-agent only inside LXD, man-db rebuilds indexes for
# manpages that this script deletes anyway.
if command -v multipath >/dev/null 2>&1 && [ -n "$(multipath -ll 2>/dev/null)" ]; then
    warn "multipath devices present; keeping multipathd"
else
    kill_units multipathd.service multipathd.socket
fi
kill_units lxd-agent.service lxd-agent-9p.service man-db.timer \
    e2scrub_all.timer e2scrub_reap.service

# cloud-init: only needed on first boot (SSH key/network/user seeding). Once it
# reports done, disabling it removes ~4 boot services and its RAM footprint.
# Never touched before completion - that would break provisioning.
if [ -x /usr/bin/cloud-init ] && [ ! -e /etc/cloud/cloud-init.disabled ]; then
    ci_status="$(cloud-init status 2>/dev/null | awk -F': ' '/status:/ {print $2}')"
    if [ "$ci_status" = "done" ]; then
        touch /etc/cloud/cloud-init.disabled
        kill_units cloud-init.service cloud-init-local.service cloud-config.service \
            cloud-final.service cloud-init.target
        log "cloud-init disabled (status was 'done'); re-enable by removing /etc/cloud/cloud-init.disabled"
        warn "New SSH keys pushed via cloud metadata will no longer be injected"
    else
        warn "cloud-init status is '${ci_status:-unknown}', not 'done': leaving it enabled"
    fi
fi

# systemd-oomd stays ON: on a small box a targeted kill beats a system-wide
# stall, and it is the counterpart to zram under memory pressure.
if unit_exists systemd-oomd.service; then
    systemctl unmask systemd-oomd.service 2>/dev/null || true
    if systemctl enable --now systemd-oomd.service 2>/dev/null; then
        log "systemd-oomd active (pressure-based OOM handling)"
    else
        warn "Could not enable systemd-oomd"
    fi
fi

# ----------------------------------------------------------- dns / journald

section "[8/9] GHOST MODE: DNS, LOGGING & CONSOLE VERBOSITY"
if [ "$DO_REPLACE_RESOLVCONF" = "1" ]; then
    echo "[DNS snapshot before change]"
    if [ -e /etc/resolv.conf ]; then
        echo "--- /etc/resolv.conf (before, target: $(readlink -f /etc/resolv.conf)) ---"
        cat /etc/resolv.conf
    else
        echo "--- /etc/resolv.conf (missing) ---"
    fi
    if command -v resolvectl >/dev/null 2>&1; then
        echo "--- resolvectl status (before) ---"
        resolvectl status 2>&1
    fi

    # Preserve search domains (and the cloud resolver on OCI) or internal names
    # like *.oraclevcn.com stop resolving.
    SEARCH_LINE="$(awk '/^[[:space:]]*(search|domain)[[:space:]]/ {print; exit}' /etc/resolv.conf 2>/dev/null)"
    if [ -z "$SEARCH_LINE" ] && command -v resolvectl >/dev/null 2>&1; then
        DOMAINS="$(resolvectl domain 2>/dev/null | tr ' ' '\n' | grep -E '\.' | grep -v ':' | sort -u | tr '\n' ' ')"
        [ -n "${DOMAINS// /}" ] && SEARCH_LINE="search ${DOMAINS%% }"
    fi

    backup_file /etc/resolv.conf
    kill_units systemd-resolved.service
    rm -f /etc/resolv.conf
    {
        echo "# Managed by ubuntu-optimizer."
        [ -n "$SEARCH_LINE" ] && echo "$SEARCH_LINE"
        [ "$IS_OCI" = 1 ] && echo "nameserver 169.254.169.254"
        echo "nameserver 1.1.1.1"
        echo "nameserver 8.8.8.8"
        echo "options timeout:2 attempts:2"
    } >/etc/resolv.conf
    chmod 644 /etc/resolv.conf
    log "DNS replaced (search='${SEARCH_LINE:-none}', oci_resolver=$IS_OCI)"
    getent hosts archive.ubuntu.com >/dev/null 2>&1 ||
        warn "DNS resolution test failed after change; restore /etc/resolv.conf.bak if needed"
else
    log "DNS handling unchanged"
fi

journalctl --vacuum-time=1s >/dev/null 2>&1 || warn "journal vacuum failed"
# Storage=volatile makes SystemMaxUse irrelevant - the live cap is RuntimeMaxUse.
write_if_changed "$JOURNALD_DROPIN" <<'EOF'
# Managed by ubuntu-optimizer.
[Journal]
Storage=volatile
RuntimeMaxUse=50M
SystemMaxUse=50M
ForwardToSyslog=no
EOF
systemctl restart systemd-journald || error "Failed to restart journald"
warn "Journal is volatile: logs do not survive reboot"
log "Logging and console verbosity reduced"

# ------------------------------------------------------------------- disk trim

section "[9/9] DISK CLEANUP"
# Config-level exclusion so docs/manpages stay gone after future installs,
# while license files (/usr/share/doc/*/copyright) are preserved.
write_if_changed /etc/dpkg/dpkg.cfg.d/01_nodoc <<'EOF'
# Managed by ubuntu-optimizer.
path-exclude=/usr/share/doc/*
path-include=/usr/share/doc/*/copyright
path-exclude=/usr/share/man/*
path-exclude=/usr/share/groff/*
path-exclude=/usr/share/info/*
path-exclude=/usr/share/lintian/*
EOF
safe_autoremove
apt_run clean || warn "apt clean failed"
find /usr/share/doc -type f ! -name copyright -delete 2>/dev/null
find /usr/share/doc -type d -empty -delete 2>/dev/null
rm -rf /usr/share/man/* /usr/share/info/* /usr/share/groff/*
rm -rf /var/lib/apt/lists/*
log "Docs/manpages trimmed; apt lists cleared (run 'apt-get update' before installing)"

# --------------------------------------------------------------- verification

section "VERIFICATION"
[ "$IS_CONTAINER" = 1 ] && warn "Container: host-only keys below are expected to be unset"
check_sysctl net.ipv4.tcp_congestion_control bbr
check_sysctl net.core.default_qdisc fq
check_sysctl vm.swappiness "$SWAPPINESS"
check_sysctl vm.page-cluster 0
check_sysctl net.core.somaxconn 65535
check_sysctl net.ipv4.ip_local_port_range "10240 65535"
check_sysctl net.core.rmem_max 33554432
check_sysctl net.ipv4.tcp_mtu_probing 1
check_sysctl fs.file-max 2097152

swap_now="$(swapon --show=NAME,SIZE,PRIO --noheadings 2>/dev/null | tr '\n' ' ')"
if printf '%s' "$swap_now" | grep -q zram; then
    log "verify OK   zram swap: $swap_now"
else
    warn "verify: no zram swap active (${swap_now:-no swap})"
fi

thp_now="$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null)"
case "$thp_now" in
    *'[madvise]'*) log "verify OK   THP = madvise" ;;
    '') warn "verify: THP not exposed by this kernel" ;;
    *) warn "verify: THP = $thp_now (expected madvise)" ;;
esac

root_opts="$(findmnt -no OPTIONS / 2>/dev/null)"
if printf '%s' "$root_opts" | grep -qE '(^|,)noatime(,|$)'; then
    log "verify OK   root mounted noatime"
else
    warn "verify: root options '$root_opts' (noatime applies after reboot if fstab was updated)"
fi

if [ "$CPU_COUNT" -gt 1 ]; then
    rps_now="$(cat /sys/class/net/*/queues/rx-*/rps_cpus 2>/dev/null | grep -vc '^0*$' || true)"
    if [ "${rps_now:-0}" -gt 0 ]; then
        log "verify OK   RPS configured on $rps_now receive queue(s)"
    else
        warn "verify: RPS masks still zero"
    fi
fi

if [ -e /etc/cloud/cloud-init.disabled ]; then
    log "verify OK   cloud-init disabled"
elif [ -x /usr/bin/cloud-init ]; then
    warn "verify: cloud-init still enabled (was not in 'done' state)"
fi

for u in fstrim.timer systemd-oomd.service; do
    unit_exists "$u" && log "verify unit $u: $(systemctl is-enabled "$u" 2>&1 | head -1)/$(systemctl is-active "$u" 2>&1)"
done

got_nofile="$(systemctl show -p DefaultLimitNOFILE --value 2>/dev/null)"
if [ "$got_nofile" = "$NOFILE_LIMIT" ]; then
    log "verify OK   systemd DefaultLimitNOFILE = $got_nofile"
else
    warn "verify PENDING systemd DefaultLimitNOFILE = ${got_nofile:-?} (expected $NOFILE_LIMIT after reboot)"
fi

if command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; then
    eff="$(${SSHD_BIN:-/usr/sbin/sshd} -T 2>/dev/null | grep -iE '^(usedns|gssapiauthentication)' | tr '\n' ' ')"
    if [ -n "$eff" ]; then
        log "verify sshd effective: $eff"
    else
        warn "verify: could not read effective sshd config"
    fi
fi

if [ -d /run/log/journal ]; then
    log "verify OK   journal is volatile (/run/log/journal)"
else
    warn "verify: /run/log/journal missing; journald storage may not be volatile"
fi

for u in snapd.service systemd-resolved.service unattended-upgrades.service; do
    unit_exists "$u" && log "verify unit $u: $(systemctl is-enabled "$u" 2>&1 | head -1)"
done

echo ""
echo "[Failed units]"
systemctl list-units --failed --no-legend 2>&1 || true
echo ""
echo "[Boot time contributors]"
systemd-analyze blame 2>/dev/null | head -10 || true
echo ""
echo "[Journal disk usage]"
journalctl --disk-usage 2>&1 || true

section "[POST] SNAPSHOT (NETWORK/DISK/PROCESSES)"
if ! command -v ss >/dev/null 2>&1; then
    apt_run update -qq || warn "apt-get update failed; ss may remain unavailable"
    if apt_run install -y iproute2 >/dev/null 2>&1; then
        log "Installed iproute2 for post-flight"
    else
        warn "Failed to install iproute2"
    fi
fi
snapshot_state >"$POST_FLIGHT_LOG" 2>&1
log "Post-flight snapshot saved to $POST_FLIGHT_LOG"

section "SUMMARY"
log "Run log: $LOG_FILE"
log "Snapshots: $PRE_FLIGHT_LOG | $POST_FLIGHT_LOG"
if [ "$FAILURES" -eq 0 ]; then
    log "OPTIMIZATION COMPLETE: REBOOT RECOMMENDED"
else
    error "COMPLETED WITH $FAILURES FAILURE(S): review $LOG_FILE before rebooting"
fi

# Let the tee child flush before the shell exits.
exec 1>&- 2>&-
wait "$TEE_PID" 2>/dev/null
[ "$FAILURES" -eq 0 ] || exit 1
exit 0
