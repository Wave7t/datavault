# Standard build and deployment

This document separates development, release construction, and production
deployment. A target host never compiles source code, and a release builder
never receives production configuration, certificates, private keys, or backup
data.

## Environment boundaries

| Environment | Responsibility | Must not do |
| --- | --- | --- |
| Developer workstation / CI | Edit code, regenerate protobufs, run tests and native development builds | Produce an unverified production install by copying dist directly |
| Release builder | Produce the portable Linux bundle and its checksums from a committed revision | Connect to a production Server or handle production credentials |
| Backup Server | Install only datavault-server, preserve rollback binaries, run Server/ZFS verification | Build Go source or overwrite configuration and ZFS data |
| Agent host | Install only dvault and datavault-agent, preserve rollback binaries, verify its Server path | Build Go source or retain user private keys |

The normal development command, make build, is intentionally native to the
machine that runs it. It is useful for development but is not a production
artifact command.

## Build a release bundle

Run the quality gate first from a clean, reviewed source revision. The release
builder refuses a dirty worktree, so BUILD-INFO always identifies the exact
code that produced the bundle:

    make ci

Then build the production bundle:

    make release-linux-amd64

The output is dist/release/linux-amd64/ and contains dvault,
datavault-agent, datavault-server, deployment scripts, BUILD-INFO, and
SHA256SUMS.

The release builder runs in Docker Buildx with a Linux/amd64 image. It uses
musl for static CGO linking and netgo for Go's DNS resolver. This is required
for portable operation on older Linux systems and avoids static glibc/NSS DNS
failures. The builder rejects an ELF binary with a dynamic interpreter and runs
each artifact's help command in a clean Linux/amd64 container before it emits
the bundle.

Inspect the manifest and verify the checksums before transfer:

    cd dist/release/linux-amd64
    cat BUILD-INFO
    sha256sum -c SHA256SUMS

On a build network that requires a different module proxy, set GOPROXY for the
build only:

    GOPROXY=https://your-approved-go-proxy,direct make release-linux-amd64

The release Docker context explicitly excludes keys, certificates, local
configuration, SQLite state, build output, and planning artifacts.

## Transfer without rebuilding

Choose a unique release directory, normally derived from BUILD-INFO's source
revision. Copy the entire bundle to a root-controlled temporary directory on
the relevant host, then validate it there:

    release=/var/tmp/datavault-release/<revision>
    sudo install -d -m 0700 $release
    # Copy the bundle through the organisation's approved transfer path.
    sudo sh -c 'cd "$1" && sha256sum -c SHA256SUMS' sh $release

Copy the Server binary and its two scripts onward to the backup Server if the
release first lands on a jump host. Copy the CLI, Agent binary, and their two
scripts to each Agent host. Do not copy config.yaml, TLS material,
authorized_keys, SQLite state, or ZFS contents as part of a binary release.

## Deploy the backup Server

On the backup Server, as root:

    cd /var/tmp/datavault-release/<revision>
    ./scripts/deploy-server.sh --artifact ./datavault-server
    ./scripts/verify-server.sh --backup-pool <zfs-pool-name>

The deployment script validates that the artifact is a static Linux/x86_64
ELF, backs up /usr/bin/datavault-server below
/var/backups/datavault/<UTC timestamp>/, atomically replaces it, and restarts
the configured systemd unit. If the replacement or restart fails, it restores
the prior binary and restarts the unit. It does not modify the Server
configuration, certificates, public-key directory, SQLite nonce state, or ZFS
datasets.

Use the actual ZFS pool name for the verification argument; it must be the
value used by the Server configuration.

## Deploy an Agent host

After the Server is healthy, run the following as root on every Agent host:

    cd /var/tmp/datavault-release/<revision>
    ./scripts/deploy-agent.sh --dvault ./dvault --agent ./datavault-agent
    ./scripts/verify-agent.sh

The Agent script saves both prior binaries together, atomically installs the
new pair, restarts the Agent, and requires the Unix socket to reappear. The
verification script checks the systemd unit and socket, then requests a Server
challenge with SSH_AUTH_SOCK deliberately removed. The expected SSH_AUTH_SOCK
not set result proves that DNS, mTLS, gRPC, and the Server's allowed-Agent
check completed before user signing. It neither signs a request nor uploads,
restores, or changes user data.

Pass --socket, --unit, or --backup-root only when the local service uses
non-default paths or unit names.

## Rollback

Each deployment script prints its backup directory. To roll back a failed
binary update, restore only the binary from that directory and restart the
corresponding unit:

    sudo install -m 0755 /var/backups/datavault/<timestamp>/datavault-server \
      /usr/bin/datavault-server.new
    sudo mv -f /usr/bin/datavault-server.new /usr/bin/datavault-server
    sudo systemctl restart datavault-server

For an Agent rollback, restore both dvault and datavault-agent from the same
timestamped directory, then restart datavault-agent. Preserve the backup
directory until the normal restore and monitoring checks have passed.

## Required production evidence

Record the release revision, SHA256SUMS verification, backup directory,
systemd start time, Server ZFS health, Agent socket check, and successful
Agent-to-Server challenge in the deployment change record. Complete the
[server preflight](server-test-preflight.md) and a real user restore before
admitting new production data or changing storage topology.
