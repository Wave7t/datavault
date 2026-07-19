#!/usr/bin/env bash
# Build a portable production bundle. This script only writes beneath dist/
# (or its caller-supplied output directory); it never contacts a target host.
set -Eeuo pipefail

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: build-release-linux-amd64.sh [OUTPUT_DIR]

Builds a self-contained, static Linux/amd64 release bundle with Docker Buildx.
An existing output directory is preserved with a UTC .previous suffix.
EOF
}

repo_root=$(cd "$(dirname "$BASH_SOURCE")/.." && pwd -P)
[[ $# -le 1 ]] || die "expected at most one output directory"
if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -eq 1 ]]; then
  output_dir=$1
else
  output_dir="$repo_root/dist/release/linux-amd64"
fi

if [[ "$output_dir" != /* ]]; then
  output_dir="$PWD/$output_dir"
fi

command -v docker >/dev/null 2>&1 || die "Docker with Buildx is required"
docker buildx version >/dev/null 2>&1 || die "Docker Buildx is required"

source_revision=$(git -C "$repo_root" rev-parse --verify HEAD) || die "cannot determine source revision"
if [[ -n $(git -C "$repo_root" status --porcelain --untracked-files=all) ]]; then
  die "refusing to build a release bundle from a dirty worktree; commit or stash the changes first"
fi

parent_dir=$(dirname "$output_dir")
bundle_name=$(basename "$output_dir")
mkdir -p "$parent_dir"
stage_dir=$(mktemp -d "$parent_dir/.$bundle_name.tmp.XXXXXX")

cleanup() {
  [[ -n $stage_dir && -d $stage_dir ]] && rm -rf "$stage_dir"
}
trap cleanup EXIT

# Set GOPROXY in constrained build networks without baking a regional mirror
# into the repository. The default remains the public Go proxy with direct
# fallback.
set +u
go_proxy=$GOPROXY
set -u
if [[ -z $go_proxy ]]; then
  go_proxy=https://proxy.golang.org,direct
fi

docker buildx build \
  --platform linux/amd64 \
  --target artifacts \
  --build-arg "VCS_REF=$source_revision" \
  --build-arg "GOPROXY=$go_proxy" \
  --output "type=local,dest=$stage_dir" \
  --file "$repo_root/Dockerfile.release" \
  "$repo_root"

for file in dvault datavault-agent datavault-server BUILD-INFO SHA256SUMS \
  scripts/deploy-server.sh scripts/deploy-agent.sh \
  scripts/verify-server.sh scripts/verify-agent.sh; do
  [[ -f "$stage_dir/$file" ]] || die "release bundle is missing $file"
done

# Running each program in a clean Linux/amd64 container catches an invalid
# target architecture or a missing dynamic loader before any deployment.
for binary in dvault datavault-agent datavault-server; do
  docker run --rm --platform linux/amd64 \
    --mount "type=bind,src=$stage_dir,dst=/release,readonly" \
    alpine:3.22 "/release/$binary" --help >/dev/null
done

if [[ -e "$output_dir" ]]; then
  previous_dir="$output_dir.previous.$(date -u +%Y%m%dT%H%M%SZ)"
  mv "$output_dir" "$previous_dir"
  printf 'previous bundle moved to %s\n' "$previous_dir"
fi

mv "$stage_dir" "$output_dir"
stage_dir=
printf 'release bundle: %s\n' "$output_dir"
printf 'source revision: %s\n' "$source_revision"
printf 'verify with: (cd %q && sha256sum -c SHA256SUMS)\n' "$output_dir"
