#!/usr/bin/env bash
# Run as root on the backup Server. This script installs an already verified
# artifact; it never builds source or alters configuration, keys, or ZFS data.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: deploy-server.sh --artifact PATH [--backup-root PATH] [--unit NAME]

Atomically installs PATH as datavault-server, restarts the systemd unit, and
keeps the prior binary in a root-only timestamped backup directory.
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

artifact=
backup_root=/var/backups/datavault
unit=datavault-server
target=/usr/bin/datavault-server

while [[ $# -gt 0 ]]; do
  case $1 in
    --artifact) artifact=$(next_value "$@"); shift 2 ;;
    --backup-root) backup_root=$(next_value "$@"); shift 2 ;;
    --unit) unit=$(next_value "$@"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n $artifact && -f $artifact ]] || die "--artifact must name a regular file"
[[ -x $artifact ]] || die "artifact is not executable"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die "release supports Linux x86_64 only"
command -v file >/dev/null 2>&1 || die "file is required to validate the release artifact"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
[[ -x $target ]] || die "existing Server binary not found at $target"

file_description=$(file -Lb "$artifact")
[[ $file_description == *"ELF 64-bit LSB executable, x86-64"* ]] || die "artifact is not Linux x86_64"
[[ $file_description == *"statically linked"* ]] || die "artifact must be statically linked"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="$backup_root/$timestamp"
backup_binary="$backup_dir/datavault-server"
[[ ! -e $backup_dir ]] || die "backup directory already exists: $backup_dir"
install -d -m 700 "$backup_dir"
cp -p "$target" "$backup_binary"
sha256sum "$backup_binary" > "$backup_dir/SHA256SUMS"

rollback() {
  printf 'deployment failed; restoring %s\n' "$backup_binary" >&2
  install -m 755 "$backup_binary" "$target.new"
  mv -f "$target.new" "$target"
  systemctl restart "$unit" || true
}

install -m 755 "$artifact" "$target.new"
mv -f "$target.new" "$target"
if ! systemctl restart "$unit" || ! systemctl is-active --quiet "$unit"; then
  rollback
  exit 1
fi

printf 'Server deployed successfully.\n'
printf 'backup: %s\n' "$backup_dir"
sha256sum "$target"
