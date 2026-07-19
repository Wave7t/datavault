#!/usr/bin/env bash
# Read-only post-deployment verification for a backup Server.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: verify-server.sh --backup-pool NAME [--unit NAME]

Checks the Server systemd unit and the health, capacity, and ZFS dataset of the
configured backup pool. It does not create, modify, or delete backup data.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

next_value() {
  [[ $# -ge 2 ]] || die "missing value for $1"
  printf '%s' "$2"
}

backup_pool=
unit=datavault-server

while [[ $# -gt 0 ]]; do
  case $1 in
    --backup-pool) backup_pool=$(next_value "$@"); shift 2 ;;
    --unit) unit=$(next_value "$@"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n $backup_pool ]] || die "--backup-pool is required"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
command -v zpool >/dev/null 2>&1 || die "zpool is required"
command -v zfs >/dev/null 2>&1 || die "zfs is required"

systemctl is-active --quiet "$unit" || die "$unit is not active"
pool_health=$(zpool list -H -o health "$backup_pool")
[[ $pool_health == ONLINE ]] || die "ZFS pool $backup_pool is $pool_health"

printf 'service=%s active\n' "$unit"
printf 'pool=%s health=%s\n' "$backup_pool" "$pool_health"
zfs list -H -o name,used,avail,mountpoint "$backup_pool"
