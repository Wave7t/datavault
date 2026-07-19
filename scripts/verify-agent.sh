#!/usr/bin/env bash
# Read-only post-deployment verification for an Agent host.
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: verify-agent.sh [--dvault PATH] [--unit NAME] [--socket PATH]

Checks the Agent service and Unix socket, then requests an unauthenticated
Server challenge. The expected SSH_AUTH_SOCK error proves the Agent reached the
Server before local user signing; no backup, restore, or user-data mutation is
performed.
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

dvault=/usr/bin/dvault
unit=datavault-agent
socket_path=/var/run/datavault-agent.sock

while [[ $# -gt 0 ]]; do
  case $1 in
    --dvault) dvault=$(next_value "$@"); shift 2 ;;
    --unit) unit=$(next_value "$@"); shift 2 ;;
    --socket) socket_path=$(next_value "$@"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -x $dvault ]] || die "dvault binary not found at $dvault"
command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
systemctl is-active --quiet "$unit" || die "$unit is not active"
[[ -S $socket_path ]] || die "Agent socket is not present: $socket_path"

set +e
challenge_output=$(env -u SSH_AUTH_SOCK "$dvault" --socket "$socket_path" quota 2>&1)
challenge_status=$?
set -e
printf '%s\n' "$challenge_output"

[[ $challenge_status -ne 0 ]] || die "unexpected quota success without SSH_AUTH_SOCK"
[[ $challenge_output == *"SSH_AUTH_SOCK not set"* ]] || die "Agent did not obtain a Server challenge"

printf 'service=%s active\n' "$unit"
printf 'socket=%s present\n' "$socket_path"
printf 'Agent-to-Server challenge verified.\n'
