# Security model

datavault is designed for a shared Linux environment in which users can back
up and restore their own data while operators retain control of the backup
infrastructure. It protects the boundaries between Unix users, Agent hosts,
and the backup Server. It is not a hostile-administrator or encrypted-storage
system.

This document describes the trust assumptions, enforcement points, and
operational obligations behind that model. Read it with the
[deployment guide](deployment.md) before enabling a production deployment.

## Scope and trust assumptions

The service assumes that the operations team controls the Server, the ZFS pool,
the private certificate authority, and the Agents installed on managed hosts.
It also assumes normal Unix account isolation on each Agent host and a private
or firewall-restricted network between Agents and Servers.

datavault does **not** provide any of the following:

- confidentiality from `root` or a privileged administrator on an Agent or
  Server host;
- encryption at rest in ZFS or an independent immutable/offsite copy;
- application-aware consistency for databases or virtual machines; or
- automatic authority for an untrusted network client to become a backup
  user.

A source-host administrator can read source files and change the Agent. A
backup-server administrator can read backup data, snapshots, configuration,
and registered public keys. Protect data requiring separation from those
administrators with an additional encryption and key-management design.

## Boundaries at a glance

```text
Unix user                  managed Agent host                 backup Server
─────────                  ──────────────────                 ─────────────
dvault CLI                 Agent (root service)               Server (root service)
  │                         │                                  │
  ├─ Unix socket ──────────►├─ UID from SO_PEERCRED             │
  │                         ├─ rule/path/restore checks         │
  │                         │                                  │
  │                         └──────── mTLS ────────────────────►├─ allowed host CN
  │                                                              ├─ user signature + nonce
  └─ SSH agent signs user operations                             ├─ host/user public key
                                                                 └─ ZFS dataset and snapshots
```

| Principal | Authority | Cannot do through normal datavault interfaces |
| --- | --- | --- |
| Unix user | Manage rules below their home, trigger user backup, inspect quota, restore below their home | Select another Unix user, source outside their home, restore outside their home, manage ZFS policy |
| Agent host | Send configured machine backups using its mTLS identity | Impersonate a different enrolled Agent without its certificate/private key |
| Backup operator | Configure hosts, storage, quotas, retention, machine rules, and enrollment policy | Use a user backup RPC to delete historical recovery snapshots |
| Server | Enforce registered host/user identities and write backup data | Treat a caller-supplied username as proof of a local Unix identity |

The table describes protocol-level boundaries. Privileged OS access is stronger
than those boundaries and remains a trusted administrative capability.

## Identity and authentication

### Local user to Agent

`dvault` communicates with the local Agent over a Unix socket. The Agent uses
Linux `SO_PEERCRED` to obtain the peer UID and resolves that UID to a Unix
account. It does not accept a username supplied by the CLI as identity.

For user-owned operations, the CLI requests a short-lived challenge from the
Server and signs the operation with a key in the user's existing SSH agent.
The Agent checks that the `SSH_AUTH_SOCK` path is an absolute Unix socket owned
by the same authenticated UID before asking that agent to sign. The Agent does
not persist user private keys.

An unlocked SSH agent is therefore signing authority for that Unix account.
Users must protect their login session and SSH-agent access, and operators
must treat an Agent host compromise as a compromise of its users' backup
authority.

### Agent to Server

Every Agent-to-Server connection uses mutually authenticated TLS with TLS 1.3
or newer. The Server verifies the client certificate and identifies the Agent
from its certificate common name (CN). The CN must be listed in the Server's
`allowed_hosts` configuration before RPCs are accepted.

The CA private key, Server private key, and Agent private keys are high-value
credentials. Store them in root-controlled locations, restrict their file
permissions, issue distinct certificates per host, and revoke/replace them
when a host is retired or suspected compromised.

### User proof at the Server

For a user backup batch, quota request, or restore request, the Server verifies
the SSH signature over the method name, a fresh nonce, and a hash of the
request. A challenge nonce expires after five minutes and is consumed once, so
a captured signed request cannot be replayed successfully.

Public keys are scoped to both the Agent and Unix username:

```text
authorized_keys/<agent-certificate-CN>/<unix-username>.pub
```

Thus a key registered for `alice` on `agent-01` is not accepted as `alice` on
another Agent, nor as another user on the same Agent. User-facing backup,
quota, and restore RPCs require this signature; administrative configuration
and machine-rule work instead rely on the authenticated Agent and operator
configuration.

### Machine rules

Machine rules are for operator-owned paths such as application or system data.
They run under the Agent's mTLS identity and do not require a user's SSH key,
which allows scheduled operation. Only operators should create them, because
their source paths are not constrained by a user's home-directory boundary.

## Authorization and data isolation

### Paths and restores

User rules are validated against the authenticated account's home directory;
sources must stay below that directory. Restore destinations are similarly
restricted below the real home directory. The Agent rejects symlinks at the
destination or parent path and verifies ownership before performing the
restore. It restores via a temporary directory and then moves the result into
place, reducing the chance of a partially restored visible target.

These checks are defence in depth, not a substitute for secure Unix ownership
and permissions. Users should avoid restoring over irreplaceable local files
without first choosing an empty or dedicated destination.

### Storage and recovery points

The Server owns ZFS dataset creation, quotas, snapshots, retention, and free
space policy. Each user's data is stored in a separate host/user dataset. A
successful backup creates a recovery snapshot; ZFS quota enforcement is the
authoritative size limit, not merely a client-side estimate.

The backup receiver rejects absolute and traversal paths and writes uploads
atomically via temporary files before rename. Restore reads from the most
recent recovery snapshot through a temporary ZFS clone, which the Server
removes after the restore stream completes.

There is no user-facing RPC for deleting recovery snapshots. A user can change
their current backed-up files through a signed sync, but historical recovery
points remain subject to the operator's retention policy. Snapshot retention
does not make the backup pool immune to Server `root`, storage failure, or a
destructive administrative action.

## Public-key enrollment

The Server supports two explicit enrollment modes in `key_enrollment.mode`.

| Mode | Who may install a user key | Intended use |
| --- | --- | --- |
| `admin_only` (default) | A backup administrator using the Server's key-management procedure | Environments that require operator approval for every identity change |
| `server_os_login` | The matching Unix account, using the Server's local enrollment socket | Managed hosts where logging in as an account is sufficient proof to authorize its backup key |

In `server_os_login` mode, the Server's enrollment socket obtains the caller's
UID with `SO_PEERCRED` and resolves it through the system account database. The
request does not carry a user-controlled username or UID. Policy can limit
enrollment to selected Agent names, named users, and a minimum UID. The Server
also requires the Agent to be an allowed host and validates the submitted SSH
public key before atomically writing the host/user-scoped public-key file.

This mode needs no `sudo`: a user who can run the enrollment command as their
own Unix account can install or replace only that account's key for an allowed
Agent. It deliberately changes the trust model: the ability to log in or run a
process as that OS account becomes sufficient authority to change its backup
authentication key. Enable it only where that is the desired account-recovery
and onboarding policy. Leave the default `admin_only` mode enabled when a
separate operator approval is required.

Public keys are identifiers, not secrets. The private key remains with the
user's SSH agent; losing or suspecting compromise of it requires replacing or
removing the registered public key and investigating backups made with that
identity.

## Production operating requirements

- Restrict the Server listen address and firewall rules to known Agent networks.
- Use a private CA, one certificate/key pair per host, and a minimal
  `allowed_hosts` list.
- Keep the Server, ZFS pool, certificate material, configuration, and key
  directory under appropriate administrative access control.
- Set explicit quotas, snapshot retention, and minimum-free-space thresholds;
  monitor their alerts and failure hooks.
- For self-service key enrollment, allow only the relevant Agents/users and
  choose a minimum UID that excludes service and system accounts.
- Test a real restore periodically and follow the
  [server preflight](server-test-preflight.md) on the actual ZFS storage.
- Maintain a second independently operated copy or offsite replication for
  data whose loss would be unacceptable. RAID is not a second backup.

## Incident response and revocation

When a user's SSH key or login session may be compromised, replace or remove
that user's registered public key, review affected backups, and have the user
create a new SSH key. When an Agent certificate/private key may be compromised,
remove the host from `allowed_hosts`, revoke or replace its certificate, and
review data received under that host identity. A suspected Server or CA
compromise requires treating every enrolled host and key mapping as suspect.

During an enrollment incident, switch `key_enrollment.mode` to `admin_only`
or disable the affected host/user policy before re-authorizing identities.
For a vulnerability in datavault itself, follow the private reporting process
in [SECURITY.md](../SECURITY.md).
