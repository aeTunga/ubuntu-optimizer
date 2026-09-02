# Ubuntu Optimizer

Performance-first optimization script for Ubuntu Server. It strips background bloat, tunes kernel/network defaults, and captures before/after snapshots plus a verification pass so you can see what actually changed.

## Features

- zram compressed swap (`min(ram, 4096)`, zstd) with swappiness raised to 100 only when the device is really up
- TCP BBR + `fq`, long-fat-pipe socket buffers (32MB), PMTU probing
- RPS: NIC receive softirqs spread over all vCPUs via `optimizer-rps.service`
- Transparent hugepages forced to `madvise` (no allocation stalls for databases/caches)
- `noatime` on `/` (fstab rewrite matched by mountpoint, reverted if `findmnt --verify` fails) + weekly `fstrim.timer`
- Snap purge (snapd, snaps, squashfs mounts) and Oracle/cloud agent cleanup
- Background service/timer trimming: unattended-upgrades, apt-daily, motd-news, fwupd, polkit/udisks/ModemManager/rpcbind, multipathd, man-db, e2scrub, ubuntu-pro timers
- cloud-init disabled once it reports `done`; `systemd-oomd` kept on as the counterpart to zram
- SSH fast-login hardening via `sshd_config.d` drop-in, validated with `sshd -t` and rolled back on error; socket-activated sshd is left socket-activated
- File-descriptor limits for both login sessions (`limits.d`) and systemd services (`DefaultLimitNOFILE`)
- Volatile journaling with a real `RuntimeMaxUse` cap, reduced console verbosity
- Disk scrubbing (docs/manpages) made permanent through `dpkg --path-exclude`
- Pre-flight, post-flight and verification logs

## Quick Start

> Run on a fresh Ubuntu install.

```bash
curl -fsSL https://raw.githubusercontent.com/aeTunga/ubuntu-optimizer/refs/heads/main/optimize.sh -o optimize.sh
sudo bash optimize.sh
```

Piping straight into `bash` also works (the confirmation prompt is read from
`/dev/tty`, and defaults to "no" when there is no terminal):

```bash
curl -fsSL https://raw.githubusercontent.com/aeTunga/ubuntu-optimizer/refs/heads/main/optimize.sh | sudo bash
```

Unattended runs:

```bash
sudo OPTIMIZER_REPLACE_RESOLVCONF=0 bash optimize.sh   # 1 = also replace /etc/resolv.conf
sudo OPTIMIZER_LOG_DIR=/root/optlogs bash optimize.sh
```

Exit code is `0` only if no step failed; otherwise `1`, with every failure
tagged `[ERROR]` in the run log.

## Safety Rails

- **sshd**: config goes to `/etc/ssh/sshd_config.d/99-optimizer.conf` (the drop-in
  wins, since sshd keeps the first value it sees). `sshd -t` must pass before the
  service is reloaded; a syntax failure is rolled back automatically.
- **Package purges**: every purge is simulated first (`apt-get -s purge`), the
  removal plan is logged, and the purge is skipped if the plan touches a
  protected package (systemd, libc6, openssh-server, cloud-init, netplan,
  linux-image, ubuntu-minimal, ...). Purges run one package at a time so a
  single package with bad collateral cannot block the rest. `autoremove` is
  gated the same way.
- **iSCSI**: `open-iscsi`/`iscsid` are kept when iSCSI sessions or `by-path`
  devices exist, and on OCI hosts in general - removing them can leave attached
  block volumes unavailable after reboot.
- **DNS**: replacing `/etc/resolv.conf` is opt-in, preserves existing `search`
  domains, keeps the cloud resolver (`169.254.169.254`) on OCI, backs up the
  real file content (not the symlink), and tests resolution afterwards.
- **ubuntu-pro-client** is not purged (apt would take `ubuntu-minimal` with it);
  its timers/services are masked instead.
- **Containers**: host-wide kernel keys are not settable inside LXC/Docker; the
  script reports what applied instead of pretending.
- **dpkg locks**: waits up to 300s for `unattended-upgrades`/`cloud-init` to
  release the frontend lock instead of failing.
- **fstab**: the root entry is matched by mountpoint (cloud images use
  `LABEL=cloudimg-rootfs`, not UUID), only its options field is touched, and the
  file is reverted from `/etc/fstab.bak` if `findmnt --verify` rejects it.
- **cloud-init**: only disabled when `cloud-init status` reports `done`, never
  mid-provisioning.
- **zram**: needs the `zram` module from `linux-modules-extra-$(uname -r)`, which
  the script installs when missing (~50MB). If the module still cannot load,
  swappiness stays at 1 instead of pointing at a device that does not exist.
- **multipathd** is kept when `multipath -ll` reports devices.

## Trade-offs You Are Accepting

- `unattended-upgrades` is purged and `apt-daily*.timer` masked: no automatic
  security updates. Patch the host yourself.
- Journal storage is volatile: logs do not survive a reboot.
- `polkitd`/`accountsservice`/`udisks2` removal is fine for headless servers,
  not for desktops.
- `apt` package lists are cleared: run `apt-get update` before installing.
- cloud-init is disabled: SSH keys or user-data pushed through cloud metadata are
  no longer applied on later boots. Environments that re-provision on every boot
  (Lima, some PaaS images) need it back: `rm /etc/cloud/cloud-init.disabled` and
  unmask the cloud-init units.
- `vm.swappiness=100` with zram is intentional: paging to compressed RAM is
  cheap. Without zram the script keeps 1.
- 32MB socket buffers are ceilings, not allocations; the kernel still autotunes
  per socket.

## Logs

Default location `/var/log/ubuntu-optimizer/` (override with `OPTIMIZER_LOG_DIR`):

- `run-<timestamp>.log` - full run output (apt, systemctl, sed included), symlinked as `latest.log`
- `preflight-<timestamp>.log` - sockets, disk, memory, top processes before changes
- `postflight-<timestamp>.log` - same snapshot after cleanup

The `VERIFICATION` block in the run log re-reads the live values
(`tcp_congestion_control`, `default_qdisc`, `swappiness`, `page-cluster`,
`somaxconn`, `ip_local_port_range`, `rmem_max`, `tcp_mtu_probing`, `file-max`,
active zram swap, THP mode, root mount options, RPS masks, cloud-init state,
`fstrim.timer`, `systemd-oomd`, `DefaultLimitNOFILE`, effective sshd config,
journal storage, failed units, boot blame) so nothing is reported as applied
without proof.

## Results

| Metric | Preflight | Postflight | Delta |
| --- | --- | --- | --- |
| RAM used | 566Mi | 288Mi | -278Mi |
| RAM available | 390Mi | 668Mi | +278Mi |
| Disk used (/) | 1.7G | 1.1G | -0.6G |
| Swap used | 0B | 0B | 0B |
