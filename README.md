# Ubuntu Optimizer

Performance-first optimization script for Ubuntu Server. It strips background bloat, tunes kernel/network defaults, and captures before/after snapshots so you can see what changed.

## Features

- Snap purge (snapd and mounts)
- Oracle/cloud agent cleanup
- TCP BBR and kernel/network tuning
- SSH fast-login hardening
- Volatile journaling and log trimming
- Disk scrubbing (docs/manpages)
- Pre-flight and post-flight snapshots to local log files

## Quick Start

> Run on a fresh Ubuntu install.

```bash
curl -fsSL https://raw.githubusercontent.com/aeTunga/ubuntu-optimizer/refs/heads/main/optimize.sh | sudo bash
```

## Logs

- `./ubuntu-optimizer.log` (main run log)
- `./ubuntu-optimizer.preflight.log` (before changes)
- `./ubuntu-optimizer.postflight.log` (after cleanup)

## Results

| Metric | Preflight | Postflight | Delta |
| --- | --- | --- | --- |
| RAM used | 566Mi | 288Mi | -278Mi |
| RAM available | 390Mi | 668Mi | +278Mi |
| Disk used (/) | 1.7G | 1.1G | -0.6G |
| Swap used | 0B | 0B | 0B |
