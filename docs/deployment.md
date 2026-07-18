# Deployment and configuration reference

Use the [README deployment tutorial](../README.md#deploy-a-first-host) for a
first host. This reference records the full configuration, runtime paths, and
operational constraints needed for repeatable deployments.

## Runtime requirements

- Linux on Agents and servers.
- ZFS tools and a mounted backup dataset on every server.
- A private CA trusted by both Agents and servers.
- An SSH agent and authorized public key for every user who runs `sync`,
  `quota`, or `restore`.
- Server-side user public keys at
  `/etc/datavault/server/authorized_keys/<agent-certificate-cn>/<username>.pub`.

The provided systemd units are templates. Set `ReadWritePaths` in
`scripts/datavault-server.service` to include the actual ZFS mount point, and
do not set `PrivateTmp=yes` for the Agent unless its user SSH-agent sockets
are deliberately bind-mounted into that namespace.

## Agent configuration

The default path is `/etc/datavault/agent/config.yaml`.

```yaml
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
  ca_file: /etc/datavault/agent/ca.pem

servers:
  - address: backup-01.example.com:8443
    # Omit when address already matches a server certificate SAN.
    tls_server_name: backup-01.example.com

machine_rules:
  - name: application-data
    paths: [/srv/app, /etc/app]
    schedule: "0 03 * * *"
    exclude: ["*.log"]
    enabled: true

retry:
  initial_interval: 60s
  max_interval: 1800s
  multiplier: 2.0
  jitter: 0.1
  max_elapsed_time: 14400s

hooks:
  on_task_failed: /usr/local/bin/datavault-task-failed
  on_quota_warning: /usr/local/bin/datavault-quota-warning

bandwidth_limit_bytes_per_second: 52428800
quota_warning_percent: 85

# Applies only to cron-triggered machine rules and supports overnight ranges.
schedule_window:
  start: "22:00"
  end: "06:00"
```

`tls_server_name` preserves server certificate verification when `address` is
an IP address, a load-balancer alias, or a container name that is not a SAN.
It is not a way to bypass TLS verification.

Agent defaults:

- Unix socket: `/var/run/datavault-agent.sock`
- SQLite state: `/var/lib/datavault/agent/state.db`
- User rules: `/etc/datavault/agent/user-rules`

Machine rules can be scheduled because they use the Agent's mTLS identity.
User backups intentionally require the invoking user's live `SSH_AUTH_SOCK`;
do not schedule them by storing a user private key in the Agent.

## Server configuration

The default path is `/etc/datavault/server/config.yaml`.

```yaml
server:
  cert_file: /etc/datavault/server/cert.pem
  key_file: /etc/datavault/server/key.pem
  ca_file: /etc/datavault/server/ca.pem
  listen: "0.0.0.0:8443"
  backup_pool: tank/backups

allowed_hosts:
  - cn: web-01

global_rules:
  - name: ssh-host-keys
    paths: [/etc/ssh]
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

- SQLite nonce state: `/var/lib/datavault/server/state.db`
- Authorized keys: `/etc/datavault/server/authorized_keys/`
- Backup layout: `<backup_pool>/<agent-certificate-cn>/<username>/`

The server creates per-host and per-user datasets, applies quotas, and creates
recovery snapshots only after a terminally successful upload. Keep the parent
backup dataset mounted and reserve enough free space for ZFS metadata and the
configured `min_free_gb` policy.

## Certificate lifecycle

`dvault cert init-ca` creates a private CA. `dvault cert issue --server` needs
at least one `--dns` or `--ip` SAN; `--client` issues the Agent credential.
The command writes certificate files with mode `0644` and private keys with
mode `0600`.

The current services load TLS material at startup. Rotate certificates by
installing the new files through your secret-management process and restarting
the affected service during a controlled maintenance window.

## User and administrator commands

```text
dvault rule add <name> <path...> [--exclude <glob>]
dvault rule remove <name>
dvault rule list
dvault rule enable <name>
dvault rule disable <name>

dvault sync trigger [--rule <name>]
dvault sync status --task <task-id>
dvault quota
dvault restore [--path <target>]

dvault admin rule add <name> <path...> [--schedule '0 3 * * *'] [--exclude <glob>]
dvault admin rule remove <name>
dvault admin rule list
```

The Agent obtains the caller identity through Unix `SO_PEERCRED`; the admin
commands require `root`. User paths must be absolute and stay below the
requesting user's home directory. Restore targets use the same restriction and
must not be symlinks.

## Operations and limits

- Probe the standard gRPC health service with a valid mTLS client certificate
  before sending production traffic.
- Task failure and quota warning hooks receive environment variables describing
  the event. Make hook scripts absolute, bounded, idempotent, and responsible
  for handing off to the organisation's alerting system.
- The service exposes health and hooks but does not embed a metrics backend,
  alert delivery service, or log collector.
- A signed restore cannot transparently fail over: obtain a new challenge and
  user signature from another configured server after a failure.

See the [server test preflight](server-test-preflight.md) for failure-injection
and real-storage validation before production admission.
