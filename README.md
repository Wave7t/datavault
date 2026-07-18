# datavault / `dvault`

[![CI](https://github.com/Wave7t/datavault/actions/workflows/ci.yml/badge.svg)](https://github.com/Wave7t/datavault/actions/workflows/ci.yml)

> Self-service backup for shared Linux servers.

`datavault` is a self-hosted backup service for small production Linux
clusters. It gives each Unix user a separate, quota-bound place for their
important data while keeping storage, retention, and system-data protection in
the hands of the operations team.

It is for the common small-team setup: a few production servers on a private
network, one ZFS-backed backup server, and people who need to protect the most
important part of their home or project directories without becoming backup
administrators.

## Why datavault

Most backup tools start from a **device** or a **repository**. That works well
when every server has one owner, or when an administrator writes and maintains
every backup job. It becomes awkward on a shared Linux host:

- users need to choose their own important directories and restore their own
  data;
- operators need to reserve capacity fairly, retain recovery points, back up
  public application data, and respond to failures;
- neither side should have to maintain a separate collection of repository
  credentials, timers, quota scripts, and restore procedures.

datavault makes the **Unix user on a shared host** the unit of self-service.
The user owns their rules and restores; the administrator owns the backup
infrastructure and its policies.

| Users manage | Administrators manage |
| --- | --- |
| Paths below their home directory | Backup servers and private-network access |
| Include/exclude rules and enabling a rule | Public or machine-level backup rules |
| Triggering a sync, checking usage, and restoring their data | ZFS storage, per-user quotas, retention, and free-space policy |
| Their backup identity | Host enrollment, certificates, alerts, and failure hooks |

This is deliberately narrower than a general endpoint-backup suite. It is not
trying to replace desktop backup, VM backup, SaaS backup, or a multi-cloud
storage platform.

## What makes it different

**A practical control plane for shared Linux servers.** Rather than asking an
operator to create a separate backup script and storage account for every
person, datavault connects a local Unix account to its own rules, storage
quota, and restore boundary.

**Storage policy is enforced where the data lives.** The server creates a ZFS
dataset per host and user. A successful upload produces a recovery snapshot;
ZFS enforces quota and the server applies retention and minimum-free-space
policy. This turns "about 100 GB each" into a real limit instead of a
spreadsheet promise.

**The system and the user have separate jobs.** Machine rules protect
administrator-owned paths such as `/srv/app` or `/etc`. User rules are limited
to the requesting user's home directory, so a personal rule cannot silently
turn into a backup of another person's files.

**Explicit identity on both hops.** A local Unix socket identifies the calling
user with `SO_PEERCRED`; Agents identify to Servers with mTLS. User operations
carry a fresh SSH-agent signature and a single-use nonce, while the Agent never
stores a reusable user private key.

```text
alice runs dvault                         operations team
       │                                          │
       │ manages ~/project and restores it        │ owns storage and policy
       ▼                                          ▼
dvault CLI ── Unix socket ── datavault-agent ── mTLS ── datavault-server
                                shared host              ZFS backup pool
                                  │                           │
                            UID boundary               host/user dataset
                                                        quota + snapshots
```

## What it does today

- Incremental, namespace-safe file backup of one or more source roots.
- Per-user rules with glob exclusions; user paths must remain below `$HOME`.
- Separate machine rules for administrator-owned directories.
- ZFS datasets per host and user, hard quotas, snapshots, and retention.
- Multiple backup servers, mTLS host enrollment, retries, transfer limits,
  health checks, and failure/quota hooks.
- User-triggered backup, quota inspection, progress reporting, and restore to
  a safe target below the user's home directory.

## Is datavault a fit?

Use datavault when all of the following are true:

- Your sources and backup servers are Linux systems on a private network.
- Several Unix users share one or more production servers.
- You want one locally operated backup pool, often a modest ZFS RAID mirror,
  with fair per-user limits.
- Operators are responsible for platform reliability, while users choose the
  important data in their own home directories.

Choose another tool when you need desktop backup, virtual-machine images,
databases with application-aware backups, cloud/SaaS data protection, or a
hostile-root confidentiality boundary. datavault defines backup-service
authorization and responsibility boundaries; it does not make source data
invisible to a privileged administrator on the source or backup host.

> **A RAID mirror is storage, not a complete backup strategy.** Use a second
> independently operated copy or site for data whose loss would be serious.
> datavault can send the same data to multiple configured backup servers.

## Quick start

The first deployment needs one Linux server with ZFS and one Linux host that
will run the Agent. Build and install on trusted hosts:

```bash
make build
sudo make install
```

Then:

1. Create a private CA and issue a Server certificate and an Agent certificate.
2. Configure the Server with its ZFS pool, allowed Agent hosts, user quota, and
   snapshot policy.
3. Configure each Agent with the Server address and any machine-level rules.
4. Authorize each user's public key, start both services, and let users create
   their own rules.

The complete, copyable deployment guide—including certificate commands,
configuration examples, and user key enrollment—is in
[Deployment and configuration](docs/deployment.md). Before production use, run
the separate [server preflight](docs/server-test-preflight.md).

Once Alice is authorized and has an `SSH_AUTH_SOCK`, her workflow is small:

```bash
dvault rule add project "$HOME/project" --exclude '**/node_modules/**'
dvault sync trigger --rule project
dvault quota
dvault restore --path "$HOME/restored"
```

Machine rules may run on an Agent schedule because they use the Agent's mTLS
identity. User-owned syncs currently require the invoking user's live SSH
agent; datavault does not retain user private keys to schedule them unattended.

## Security and operational model

- **Private-network service:** bind the Server to a firewall-restricted
  interface and verify all Agent connections with mTLS.
- **User boundary:** the Agent derives the caller from the Unix socket peer,
  not from a client-supplied username. User paths and restore targets are
  restricted to that account's home directory.
- **Operator boundary:** only the Server manages ZFS datasets, quotas, and
  snapshots. The backup RPC has no delete-snapshot operation.
- **Key custody:** user private keys remain in the user's SSH agent; the
  Server verifies the matching public key for signed user operations.
- **Production validation:** test a restore and follow the
  [server preflight](docs/server-test-preflight.md) on real ZFS storage before
  trusting a deployment with production data.

The [security model](docs/security-model.md) explains the trust boundaries,
signed-request flow, key-enrollment modes, and limitations in detail.

## Project direction

datavault is intentionally an open-source tool for a focused operational
problem, not a feature-for-feature alternative to commercial backup suites.
The most useful future work is work that makes the shared-server model easier
to adopt and operate:

- user-approved, revocable policies for unattended user backups;
- point-in-time snapshot browsing and restore verification;
- identity onboarding, observability, and deployable small-cluster defaults;
- encrypted offsite replication or a second independent backup target.

If you operate a shared Linux cluster, have been maintaining per-user backup
scripts, or want to contribute around these boundaries, please open an issue
with the deployment and recovery workflow you need.

## Documentation

- [Deployment and configuration reference](docs/deployment.md)
- [Security model](docs/security-model.md)
- [Server test preflight](docs/server-test-preflight.md)
- [Development guide](docs/development.md)
- [Contributing](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## License

datavault is released under the [MIT License](LICENSE).
