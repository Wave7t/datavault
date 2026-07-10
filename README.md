# datavault / dvault

`datavault` is a Go-based incremental backup prototype for Linux clusters. It is designed for disaster recovery: clients periodically scan configured paths, send changed files to one or more backup servers, and the server stores data in per-host/per-user ZFS datasets with quotas and snapshots.

The project currently builds three binaries:

- `dvault` — user/admin CLI that talks to the local agent over a Unix socket.
- `datavault-agent` — client-side daemon that schedules scans, computes diffs, and pushes/restores data.
- `datavault-server` — backup storage daemon that accepts mTLS gRPC connections and manages ZFS-backed storage.

The reviewed design document is in `docs/superpowers/specs/2026-07-09-datavault-design.md`.

## Architecture

```text
dvault CLI
  -> gRPC over Unix socket, peer identity from SO_PEERCRED

datavault-agent
  -> gRPC over TCP + mTLS

datavault-server
  -> ZFS datasets, quota, snapshots, restore stream
```

Server-side storage layout follows this shape:

```text
<backup_pool>/
  <hostname>/
    <username>/
    _machine/
```

User rules are stored on the agent host, machine rules live in the agent config, and global forced rules/quota policy live in the server config.

## Current Implementation Status

Implemented and covered by tests:

- User rule CRUD through `dvault rule ...`.
- Machine rule CRUD through `dvault admin rule ...`.
- Agent peer identity via Unix socket `SO_PEERCRED`.
- Incremental scan/diff based on local SQLite snapshots.
- Batched backup push with real file contents and delete markers.
- `_machine` sync path for agent `machine_rules` using mTLS-only server authentication.
- Quota query through `dvault quota` with CLI-side SSH signing.
- Full restore of latest server data through `dvault restore` with CLI-side SSH signing and local path validation.
- Server-side ZFS dataset/quota/snapshot helpers.

Important limitations:

- User backup batch signing is still performed by the agent process after scanning/packing. The design target is CLI-side signing for all user-authorized operations; quota and restore already follow that model, but sync still needs a protocol redesign.
- Certificate/CA provisioning commands described in the design spec are not implemented as CLI subcommands.
- Retry classification, failure hooks, bandwidth limiting, and scheduler time-window enforcement are only partially represented or not wired through the main sync path.
- Restore currently reads from the first configured server; it does not automatically fail over to later servers.
- The systemd unit files are provided as deployment templates and may need adjustment for your init environment.

## Prerequisites

Development:

- Go 1.25 or compatible with `go.mod`.
- `buf` for protobuf regeneration.
- CGO-capable toolchain for `github.com/mattn/go-sqlite3`.

Runtime:

- Linux.
- ZFS tools available on the server host.
- mTLS certificates for agent/server gRPC.
- An SSH agent with an authorized user key for user operations that require signatures (`quota`, `restore`, and eventually full user sync authorization).
- Server-side authorized keys under `/etc/datavault/server/authorized_keys/<hostname>/<username>.pub`.

## Build and Test

```bash
make build
```

This runs protobuf generation and builds all binaries into `dist/`.

Useful development commands:

```bash
buf generate
go test ./...
go vet ./...
gofmt -w <changed-go-files>
```

The repository also provides:

```bash
make test
make clean
sudo make install
```

`make install` copies binaries into `/usr/bin` and installs the sample systemd units from `scripts/`.

## Configuration

### Agent Config

Default path: `/etc/datavault/agent/config.yaml`

```yaml
agent:
  cert_file: "/etc/datavault/agent/cert.pem"
  key_file: "/etc/datavault/agent/key.pem"

servers:
  - address: "backup-01.example.com:8443"

machine_rules:
  - name: "app-config"
    paths: ["/opt/app/config", "/opt/app/data"]
    schedule: "0 3 * * *"
    exclude: ["*.log"]
    enabled: true

retry:
  initial_interval: 60s
  max_interval: 1800s
  multiplier: 2.0
  jitter: 0.1
  max_elapsed_time: 14400s

hooks:
  on_task_failed: "/usr/local/bin/datavault-alert.sh"
  on_quota_warning: "/usr/local/bin/datavault-quota-warn.sh"
```

Agent defaults:

- Config: `/etc/datavault/agent/config.yaml`
- Socket: `/var/run/datavault-agent.sock`
- SQLite state: `/var/lib/datavault/agent/state.db`
- User rules: `/etc/datavault/agent/user-rules`

### Server Config

Default path: `/etc/datavault/server/config.yaml`

```yaml
server:
  cert_file: "/etc/datavault/server/cert.pem"
  key_file: "/etc/datavault/server/key.pem"
  listen: "0.0.0.0:8443"
  backup_pool: "tank/backups"

allowed_hosts:
  - cn: "web-01.example.com"

global_rules:
  - name: "ssh-host-keys"
    paths: ["/etc/ssh"]
    exclude: ["*.pub"]

user_policy:
  default_schedule: "30 3 * * *"
  default_quota_gb: 20
  per_user_overrides:
    alice:
      quota_gb: 100

snapshot_policy:
  min_snapshots: 2
  max_snapshots: 7
  min_free_gb: 1000
```

Server defaults:

- Config: `/etc/datavault/server/config.yaml`
- SQLite state: `/var/lib/datavault/server/state.db`
- Authorized keys: `/etc/datavault/server/authorized_keys/<hostname>/<username>.pub`

## Running Locally

Start the server:

```bash
datavault-server --config /etc/datavault/server/config.yaml
```

Start an agent:

```bash
datavault-agent \
  --config /etc/datavault/agent/config.yaml \
  --socket /var/run/datavault-agent.sock \
  --db /var/lib/datavault/agent/state.db \
  --rules-dir /etc/datavault/agent/user-rules
```

Then use `dvault`:

```bash
dvault rule add docs ~/Documents --exclude '**/*.tmp'
dvault rule list
dvault sync trigger
dvault sync status --task <task-id>
dvault quota
dvault restore --path ~/restored
```

Use a custom agent socket if needed:

```bash
dvault --socket /tmp/datavault-agent.sock rule list
```

## CLI Reference

User commands:

```bash
dvault rule add <name> <path...> [--exclude <glob>]
dvault rule remove <name>
dvault rule list
dvault rule enable <name>
dvault rule disable <name>

dvault sync trigger [--rule <name>]
dvault sync status --task <task-id>

dvault quota
dvault restore [--path <target>]
```

Admin commands:

```bash
dvault admin rule add <name> <path...> [--schedule '0 3 * * *'] [--exclude <glob>]
dvault admin rule remove <name>
dvault admin rule list
```

Admin rule commands require the caller to be `root` according to the agent's Unix socket peer credentials.

## Security Model

- CLI-to-agent identity uses Unix socket `SO_PEERCRED`; the agent ignores user-supplied usernames.
- Agent-to-server machine identity uses mTLS certificate CN and the server `allowed_hosts` list.
- User `quota` and `restore` use CLI-side SSH signing: the CLI requests a server nonce through the agent, signs the server request payload with `ssh-agent`, and the agent forwards the nonce/signature.
- Machine backup rules write to `_machine` and are authenticated by mTLS only.
- Server file writes include path traversal checks before writing into the ZFS-backed mount tree.
- Restore target paths must be under the requesting user's home directory, must not be symlinks, and must be owned by the requesting UID.

## Development Notes

Generated protobuf files are checked in. If you edit `pkg/agentpb/v1/agent.proto` or `pkg/backuppb/v1/backup.proto`, regenerate them with:

```bash
buf generate
```

Run the full validation suite before submitting changes:

```bash
gofmt -w $(git ls-files '*.go')
go test ./...
go vet ./...
git diff --check
```

Avoid running `gofmt` on `.proto` files.

## Repository Layout

```text
cmd/dvault/              CLI
cmd/datavault-agent/     client daemon
cmd/datavault-server/    server daemon
internal/agent/          agent-only orchestration, scheduler, service, transport
internal/server/         server-only middleware, receiver, service
pkg/agentpb/             AgentService protobuf definitions and generated Go
pkg/backuppb/            BackupService protobuf definitions and generated Go
pkg/auth/                SSH signing and Unix peer credential helpers
pkg/config/              YAML config loaders
pkg/glob/                exclude pattern matching
pkg/packager/            backup batch splitting
pkg/progress/            task progress tracker
pkg/rules/               rule storage and merge logic
pkg/scanner/             filesystem scan and diff logic
pkg/store/               SQLite state tables
pkg/zfs/                 ZFS command wrappers
scripts/                 systemd unit templates
docs/superpowers/        design specs and implementation plan notes
```
