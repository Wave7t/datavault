# Development guide

## Architecture

```text
dvault CLI
  -> gRPC over Unix socket, peer identity from SO_PEERCRED
datavault-agent
  -> gRPC over TCP with mTLS
datavault-server
  -> ZFS datasets, quotas, snapshots, and restore stream
```

The CLI is the user-facing authorization boundary. The Agent performs scans,
diffs, schedules machine rules, and manages local SQLite state. The server
enforces mTLS host identity and signed user operations, then writes to ZFS.

## Prerequisites

- Go 1.25 or the version declared in `go.mod`.
- `buf` for Protocol Buffer generation and linting.
- A CGO-capable toolchain for `github.com/mattn/go-sqlite3`.
- Docker and a ZFS-capable Linux environment for the opt-in loop-ZFS tests.

## Build and test

```bash
make build
make test
make ci
```

`make build` regenerates Protocol Buffer code and writes binaries to `dist/`.
`make ci` is the canonical quality gate: formatting, module tidiness, Protocol
Buffer format/lint/generated checks, `go vet`, race-enabled tests, and builds.
Neither command creates a portable production bundle. Use
make release-linux-amd64 only after the quality gate; it runs the isolated
musl/static Linux release builder described in
[Standard build and deployment](release-and-deploy.md).

For focused work:

```bash
go test ./internal/agent/orchestrator
go test ./pkg/store
gofmt -w <changed-go-files>
```

## Protocol Buffer changes

Generated Protocol Buffer files are checked in. After editing
`pkg/agentpb/v1/agent.proto` or `pkg/backuppb/v1/backup.proto`, run:

```bash
buf format -w
buf generate
make generate-check
```

Do not run `gofmt` on `.proto` files.

## Repository layout

```text
cmd/dvault/              CLI
cmd/datavault-agent/     Agent daemon
cmd/datavault-server/    Server daemon
internal/agent/          agent orchestration, scheduler, service, transport
internal/server/         server middleware, receiver, service
pkg/agentpb/             AgentService protobuf API and generated Go
pkg/backuppb/            BackupService protobuf API and generated Go
pkg/auth/                SSH signing and Unix peer-credential helpers
pkg/config/              YAML configuration loaders
pkg/hooks/               bounded operational hooks
pkg/pki/                 private-CA and certificate support
pkg/scanner/             filesystem scan and diff logic
pkg/store/               SQLite state tables
pkg/zfs/                 ZFS command wrappers
integration/loopzfs/     opt-in loop-backed ZFS tests
scripts/                 systemd unit templates
docs/                    deployment, validation, and contributor docs
```

## Validation layers

Run `make ci` for every change. Changes affecting transport, recovery,
authentication, ZFS commands, or certificates should also be exercised against
the [server test preflight](server-test-preflight.md). The loop-backed tests
verify application behavior but do not replace real-disk, ZFS-topology, or
power-loss validation.
