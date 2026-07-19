#!/usr/bin/env bash
# Run as root on an Agent host. It installs pre-built artifacts only and keeps
# both replaced binaries together in a root-only rollback directory.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: deploy-agent.sh --dvault PATH --agent PATH [--backup-root PATH] [--unit NAME] [--socket PATH]

Atomically installs dvault and datavault-agent artifacts, restarts the Agent
unit, verifies its Unix socket, and retains the prior pair for rollback.
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

dvault_artifact=
agent_artifact=
backup_root=/var/backups/datavault
unit=datavault-agent
socket_path=/var/run/datavault-agent.sock
dvault_target=/usr/bin/dvault
agent_target=/usr/bin/datavault-agent

while [[ $# -gt 0 ]]; do
  case $1 in
    --dvault) dvault_artifact=$(next_value "$@"); shift 2 ;;
    --agent) agent_artifact=$(next_value "$@"); shift 2 ;;
    --backup-root) backup_root=$(next_value "$@"); shift 2 ;;
    --unit) unit=$(next_value "$@"); shift 2 ;;
    --socket) socket_path=$(next_value "$@"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -f $dvault_artifact && -x $dvault_artifact ]] || die "--dvault must name an executable file"
[[ -f $agent_artifact && -x $agent_artifact ]] || die "--agent must name an executable file"
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die "release supports Linux x86_64 only"
command -v file >/dev/null 2>&1 || die "file is required to validate release artifacts"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
[[ -x $dvault_target && -x $agent_target ]] || die "existing Agent binaries are missing"

for artifact in "$dvault_artifact" "$agent_artifact"; do
  file_description=$(file -Lb "$artifact")
  [[ $file_description == *"ELF 64-bit LSB executable, x86-64"* ]] || die "$artifact is not Linux x86_64"
  [[ $file_description == *"statically linked"* ]] || die "$artifact must be statically linked"
done

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="$backup_root/$timestamp"
[[ ! -e $backup_dir ]] || die "backup directory already exists: $backup_dir"
install -d -m 700 "$backup_dir"
cp -p "$dvault_target" "$backup_dir/dvault"
cp -p "$agent_target" "$backup_dir/datavault-agent"
sha256sum "$backup_dir/dvault" "$backup_dir/datavault-agent" > "$backup_dir/SHA256SUMS"

rollback() {
  printf 'deployment failed; restoring binaries from %s\n' "$backup_dir" >&2
  install -m 755 "$backup_dir/dvault" "$dvault_target.new"
  install -m 755 "$backup_dir/datavault-agent" "$agent_target.new"
  mv -f "$dvault_target.new" "$dvault_target"
  mv -f "$agent_target.new" "$agent_target"
  systemctl restart "$unit" || true
}

install -m 755 "$dvault_artifact" "$dvault_target.new"
install -m 755 "$agent_artifact" "$agent_target.new"
if ! mv -f "$dvault_target.new" "$dvault_target" \
  || ! mv -f "$agent_target.new" "$agent_target"; then
  rollback
  die "could not install the complete Agent binary pair"
fi

if ! systemctl restart "$unit" || ! systemctl is-active --quiet "$unit"; then
  rollback
  exit 1
fi

for _ in $(seq 1 10); do
  [[ -S $socket_path ]] && break
  sleep 1
done
if [[ ! -S $socket_path ]]; then
  rollback
  die "Agent socket was not created: $socket_path"
fi

printf 'Agent and CLI deployed successfully.\n'
printf 'backup: %s\n' "$backup_dir"
sha256sum "$dvault_target" "$agent_target"
