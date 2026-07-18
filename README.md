# datavault / dvault

[![CI](https://github.com/Wave7t/datavault/actions/workflows/ci.yml/badge.svg)](https://github.com/Wave7t/datavault/actions/workflows/ci.yml)

`datavault` is a Linux backup system for hosts that need incremental file
backup, user-controlled authorization, and ZFS recovery points in one
deployment.

## Why datavault

Most file-copy backup tools either run with a broad service credential or
leave snapshot, quota, and recovery policy to separate tooling. datavault
combines those concerns while keeping their authority boundaries explicit:

- **A user signs each user backup.** The root-run Agent verifies the local
  Unix-socket peer and asks that user's SSH agent to authorize every batch;
  it does not retain a reusable user private key.
- **ZFS is part of the durability contract.** A successful backup creates a
  recovery snapshot in a per-host, per-user dataset with quota and retention
  policy, rather than merely copying files to a directory.
- **Incremental changes are namespace-safe.** Source-root prefixes prevent
  same-named files from independent roots from colliding. Mode-only changes,
  deletes, large-file chunks, and atomic restore writes are preserved.
- **The transport is designed for operations.** mTLS identifies backup hosts;
  signed user operations use single-use nonces. Retry bounds, transfer limits,
  scheduling windows, health checks, and hooks are built into the control
  path.

It builds three binaries: `dvault` (CLI), `datavault-agent` (host-side agent),
and `datavault-server` (ZFS-backed backup service).

## Deploy a first host

This tutorial deploys one server, `backup-01.example.com`, and one Agent,
`web-01`. Use a secure configuration-management or secret-distribution system
when the CA and Agent credentials cross machines.

### 1. Prepare the server and install datavault

The server needs Linux, ZFS tools, and an existing dataset for backups. Build
the release on a trusted build host, then install the binaries and systemd
units on the target hosts:

```bash
make build
sudo make install
```

Create or select a ZFS dataset such as `tank/backups`. The service discovers
its ZFS mount point at startup. The bundled service units intentionally use a
systemd 219-compatible baseline, including CentOS 7.

### 2. Create the private CA and issue certificates

Run these commands as root on the CA host. The server certificate SAN must
match the name that Agents verify.

```bash
sudo dvault cert init-ca

sudo dvault cert issue --server \
  --common-name backup-01.example.com \
  --dns backup-01.example.com \
  --cert /etc/datavault/server/cert.pem \
  --key /etc/datavault/server/key.pem

sudo dvault cert issue --client \
  --common-name web-01 \
  --cert /etc/datavault/agent/cert.pem \
  --key /etc/datavault/agent/key.pem
```

Install the CA certificate at `/etc/datavault/server/ca.pem` on the server and
`/etc/datavault/agent/ca.pem` on the Agent. Install the Agent certificate and
key only on `web-01`; private keys must remain mode `0600`.

### 3. Configure the server and Agent

Create `/etc/datavault/server/config.yaml`:

```yaml
server:
  cert_file: /etc/datavault/server/cert.pem
  key_file: /etc/datavault/server/key.pem
  ca_file: /etc/datavault/server/ca.pem
  # Bind the server's private interface, not a public address.
  listen: "10.20.0.10:8443"
  backup_pool: tank/backups

allowed_hosts:
  - cn: web-01

user_policy:
  default_quota_gb: 20

snapshot_policy:
  min_snapshots: 2
  max_snapshots: 7
  min_free_gb: 100
```

Create `/etc/datavault/agent/config.yaml` on `web-01`:

```yaml
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
  ca_file: /etc/datavault/agent/ca.pem

servers:
  - address: backup-01.example.com:8443

machine_rules:
  - name: application-data
    paths: [/srv/app]
    schedule: "0 03 * * *"
    enabled: true
```

If routing uses an IP address, load-balancer name, or container alias that is
not present in the server certificate, set `tls_server_name` to a certificate
DNS/IP SAN. Do not disable TLS verification.

The Agent writes service logs to `/var/log/datavault/agent.log`; `make install`
installs a daily rotation policy that retains 14 compressed copies. This avoids
an incompatibility between systemd 219's journal stream and the static Agent
binary.

### 4. Authorize users and start the services

For a user backup, place that user's SSH public key on the server. The first
directory component is the Agent certificate CN (`web-01` here):

```bash
sudo install -d -m 0755 /etc/datavault/server/authorized_keys/web-01
sudo install -m 0644 /path/to/alice.pub \
  /etc/datavault/server/authorized_keys/web-01/alice.pub

sudo systemctl enable --now datavault-server
sudo systemctl enable --now datavault-agent
```

### 5. Run the first backup and restore

From Alice's login session on `web-01`, with `SSH_AUTH_SOCK` available:

```bash
dvault rule add documents "$HOME/Documents" --exclude '**/*.tmp'
dvault sync trigger
dvault quota
dvault restore --path "$HOME/restored"
```

Use `dvault sync status --task <task-id>` to follow a backup. Validate the
complete installation, including mTLS health and a restore checksum, with the
[server test preflight](docs/server-test-preflight.md) before admitting
production data.

## Documentation

- [Deployment and configuration reference](docs/deployment.md)
- [Server test preflight](docs/server-test-preflight.md)
- [Development guide](docs/development.md)
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md)

## Production scope

datavault has passed application-level loop-backed ZFS validation, including
mTLS health, incremental backup, signed user restore, and nonce replay
rejection. A file-backed pool does not validate real disks or operational
response: complete the preflight against the intended ZFS topology, monitoring
and alert delivery, and power-loss recovery before production admission.

The main protocol limitation is restore failover: after a user signs a
server-specific nonce, a failed restore needs a fresh challenge and signature
from another configured server.

## License

This project is released under the [MIT License](LICENSE).
