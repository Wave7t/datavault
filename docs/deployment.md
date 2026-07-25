# Deployment and configuration reference

Use the [README deployment tutorial](../README.md#deploy-a-first-host) for a
first host. This reference records the full configuration, runtime paths, and
operational constraints needed for repeatable deployments.

## Runtime requirements

- Linux on Agents and servers.
- ZFS tools and a mounted backup dataset on every server.
- `getent` with the server's configured NSS sources. The Server uses it to
  resolve the kernel-authenticated local UID during self-service key
  enrollment, including when accounts come from LDAP or another NSS backend.
- A private CA trusted by both Agents and servers.
- An SSH agent and authorized public key for every user who runs `sync`,
  `quota`, or `restore`.
- Server-side user public keys at
  `/etc/datavault/server/authorized_keys/<agent-certificate-cn>/<username>.pub`.

The provided systemd units use a systemd 219-compatible baseline, so they work
on CentOS 7 as well as newer distributions. They deliberately do not use
`ProtectSystem=strict` or `ReadWritePaths`, which systemd 219 does not parse.
The Agent must retain `PrivateTmp=no` unless user SSH-agent sockets are
deliberately bind-mounted into a private namespace.

The Agent writes service logs to `/var/log/datavault/agent.log`. `make install`
creates that directory and installs `scripts/datavault-agent.logrotate`, which
rotates the log daily and retains 14 compressed copies. File logging avoids a
verified `SIGPIPE` failure mode in the systemd 219 journal stream with the
static Agent binary.

## Administrator-managed SSH-agent availability

User-owned `dvault sync`, `dvault quota`, and `dvault restore` operations need
an SSH agent that is live in the user's login session. The agent must contain
the public key registered for that `(Agent CN, Unix username)` identity. This
is a user authentication requirement, not an Agent daemon credential: do not
put user private keys in `/etc/datavault`, in the Agent configuration, or in a
root-owned script.

The recommended arrangement for users who SSH to an Agent host (for example, a
relay) is **host-specific SSH-agent forwarding**. Configure it centrally on
managed client machines, rather than enabling forwarding for every SSH target:

```sshconfig
# /etc/ssh/ssh_config.d/60-datavault-relay.conf
Host relay.example.com relay
    ForwardAgent yes
```

On the relay, ensure the SSH server permits it (this is commonly the default,
but set it explicitly when datavault depends on it):

```text
# /etc/ssh/sshd_config.d/60-datavault.conf
AllowAgentForwarding yes
```

Reload the SSH daemon with the distribution-appropriate command, for example
`systemctl reload sshd`. A user still loads their own private key on the
managed client (`ssh-add`); forwarding makes that user's existing
`SSH_AUTH_SOCK` available on the relay without copying the private key there.
Restrict the `Host` entry to datavault relays: a forwarded agent lets the
remote host request signatures while the session is active.

For users who log in directly to the relay and do not use forwarding, an
administrator can install one of the following interactive-shell snippets.
They reuse a valid session agent when available, recover a valid per-user
agent started by a previous shell, and otherwise start a new per-user agent.
They never add a private key automatically; the user must run `ssh-add` and
enter any passphrase themselves.

For Bourne-compatible login shells, install this as
`/etc/profile.d/datavault-ssh-agent.sh` with mode `0644`:

```sh
# Do nothing for non-interactive shells or a forwarded/otherwise valid agent.
case $- in
  *i*) ;;
  *) return ;;
esac

dvault_ssh_agent_env="$HOME/.ssh/datavault-ssh-agent.sh"
if [ -z "${SSH_AUTH_SOCK:-}" ] || [ ! -S "$SSH_AUTH_SOCK" ]; then
  if [ -r "$dvault_ssh_agent_env" ]; then
    . "$dvault_ssh_agent_env" >/dev/null
  fi
fi
if [ -z "${SSH_AUTH_SOCK:-}" ] || [ ! -S "$SSH_AUTH_SOCK" ]; then
  mkdir -p "$HOME/.ssh"
  (umask 077; ssh-agent -s >"$dvault_ssh_agent_env")
  chmod 600 "$dvault_ssh_agent_env"
  . "$dvault_ssh_agent_env" >/dev/null
fi
unset dvault_ssh_agent_env
```

For `csh`/`tcsh`, place the equivalent in `/etc/csh.cshrc` (or the
distribution's system-wide `csh` startup file). The `prompt` guard is important
because it prevents non-interactive jobs from creating background agents:

```csh
if ($?prompt) then
    set dvault_ssh_agent_env = "$HOME/.ssh/datavault-ssh-agent.csh"
    set dvault_need_ssh_agent = 0
    if (! $?SSH_AUTH_SOCK) then
        set dvault_need_ssh_agent = 1
    else if (! -S "$SSH_AUTH_SOCK") then
        set dvault_need_ssh_agent = 1
    endif
    if ($dvault_need_ssh_agent && -r "$dvault_ssh_agent_env") then
        source "$dvault_ssh_agent_env" > /dev/null
        set dvault_need_ssh_agent = 0
        if (! $?SSH_AUTH_SOCK) then
            set dvault_need_ssh_agent = 1
        else if (! -S "$SSH_AUTH_SOCK") then
            set dvault_need_ssh_agent = 1
        endif
    endif
    if ($dvault_need_ssh_agent) then
        if (! -d "$HOME/.ssh") mkdir -m 700 "$HOME/.ssh"
        (umask 077; ssh-agent -c) >! "$dvault_ssh_agent_env"
        chmod 600 "$dvault_ssh_agent_env"
        source "$dvault_ssh_agent_env" > /dev/null
    endif
    unset dvault_ssh_agent_env
    unset dvault_need_ssh_agent
endif
```

After the first direct login, the user must load the intended key and verify
it. Datavault currently signs with the first key returned by the SSH agent, so
the registered public key must match the first output line:

```bash
ssh-add ~/.ssh/id_ed25519
test -S "$SSH_AUTH_SOCK"
ssh-add -L | sed -n '1p'
dvault quota
```

Do not source the generated per-user environment file from a privileged shell.
It is deliberately user-owned and contains only that user's SSH-agent
environment. The root-running datavault Agent does not inherit this environment:
the CLI passes the socket path for each request, and the Agent verifies that it
is an absolute Unix socket owned by the calling UID. Keep the supplied Agent
systemd unit's `PrivateTmp=no` setting unless an equivalent shared socket path
is explicitly bind-mounted into a private namespace.

## OS-account key enrollment

The default key trust mode is `admin_only`: an administrator creates the
root-owned public-key file for each `(Agent CN, username)` pair. This is the
right default when the backup server's local account authentication is not an independent
identity authority.

An administrator can explicitly trust eligible backup-server OS accounts to enroll a
key for their own datavault identity. This is useful when users can already
log in to the backup server under the same account name and that login is protected by the
organisation's SSH and PAM policy. Enable only the Agent identities that the
accounts should be able to use:

```yaml
key_enrollment:
  mode: server_os_login
  server_os_login:
    allowed_agents: [web-01]
    # Used when allowed_users is absent. System accounts are excluded.
    min_uid: 1000
    # Alternatively, use an explicit allow-list instead of the UID threshold.
    # allowed_users: [alice, bob]
```

Every `allowed_agents` value must also be present in `allowed_hosts`; this
prevents a policy typo from granting enrollment rights to a host that cannot
connect to the backup service. Leave this block absent, or set
`mode: admin_only`, to keep administrator-only key management.

The policy does not make `/etc/datavault/server/authorized_keys` user-writable
and requires no `sudo` rule. The root-running `datavault-server` daemon owns
`/var/run/datavault-key-enroll.sock` (mode `0666`). On Linux it obtains the
connecting process's UID with `SO_PEERCRED`, resolves that UID to its backup-server OS
account, and ignores any caller-supplied identity. It therefore accepts a
request only for the account that is actually logged in to the backup server.

The unprivileged `key-enroll` client accepts exactly one public key on standard
input, checks that the key is not a certificate, and rejects RSA keys below
3072 bits. The daemon may only atomically replace this root-owned file:

```text
/etc/datavault/server/authorized_keys/<allowed-agent-cn>/<authenticated-os-user>.pub
```

The installed file has mode `0644`; its parent directories remain root-owned.
The client reports only the key fingerprint, not private-key material. The
Server journal records the authenticated OS account, UID, Agent CN, and
fingerprint. No restart is needed after enrollment because authorization keys
are loaded per request.

For a user whose current SSH Agent key is the first key listed by
`ssh-add -L`, enrollment can be run from the relay as follows:

```bash
ssh-add -L | sed -n '1p' |
  ssh backup-01.example.com \
    '/usr/bin/datavault-server key-enroll --agent web-01'
```

Using the first SSH-Agent key is important: current user operations sign with
that key. The account needs only to log in to the backup server and be eligible under the
configured `min_uid` (or explicit `allowed_users`) policy; it does not need
`sudo`, group membership, or write access to `/etc`. After enrollment, run
`dvault quota` on the relay to verify the end-to-end binding.

Treat this mode as equivalent to delegating backup-key management to a backup-server OS
account. A compromise of an eligible account can enroll an attacker key
for that same user's historical backups. Require strong SSH authentication
(preferably public-key authentication plus MFA), use a sensible `min_uid` to
exclude system accounts, and disable the OS account promptly when it is no
longer trusted.

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
  # Bind a private interface whenever Agents reach this server privately.
  listen: "10.20.0.10:8443"
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
recovery snapshots only after a terminally successful upload. At startup it
verifies that the configured backup pool is mounted; before each write it also
mounts the target host and user datasets. Keep the parent backup dataset
mounted and reserve enough free space for ZFS metadata and the configured
`min_free_gb` policy.

Do not bind the service to a public interface unless that exposure is a
deliberate, firewall-restricted design. Ensure every Agent `servers.address`
host or `tls_server_name` is present as a DNS or IP SAN in the server
certificate.

## Web gateway integration (optional)

The Agent can expose an optional HTTPS API so a web backend ("gateway") can
integrate datavault into a web UI on behalf of enrolled users. The feature is
disabled unless an `https_api` block is present in the Agent configuration; an
Agent without it behaves byte-for-byte as today.

Enable it only when a trusted web backend must drive user backup, quota, and
restore flows remotely. The gateway is a new trust principal: once a user
enrolls it, the gateway's certificate plus an unlocked delegation key are
signing authority for that user's backup operations until expiry or revocation
(see [Security model: web gateway delegations](security-model.md#web-gateway-delegations)).
Do not enable it for Agents whose only callers are local users.

### Configuration

Add the `https_api` section to `/etc/datavault/agent/config.yaml`:

```yaml
https_api:
  listen: "10.0.0.5:8443"
  cert_file: /etc/datavault/agent/https.crt
  key_file:  /etc/datavault/agent/https.key
  ca_file:   /etc/datavault/agent/ca.crt
  gateway_cns: ["backup-web-01"]
  delegation_ttl: 720h   # default max delegation lifetime; enroll may shorten
  min_uid: 1000          # accounts below this cannot be delegated or addressed
```

Field notes:

- `listen` — the HTTPS listener address. Bind a private interface and restrict
  it to gateway subnets with the host firewall (see below); do not expose it on
  a public interface.
- `cert_file` / `key_file` — the listener's server certificate and private key,
  issued by the same private CA as Agent↔Server mTLS (no public CA). The CN is
  the Agent host name and is presented to the gateway.
- `ca_file` — the private CA certificate used to verify gateway client
  certificates. Reuse the Agent's existing `ca_file`; there is no system root
  fallback.
- `gateway_cns` — allowlist of gateway client-certificate CNs. A CA-issued
  certificate whose CN is not listed is rejected, so another Agent's cert cannot
  masquerade as a gateway. At least one CN is required.
- `delegation_ttl` — default maximum delegation lifetime applied at enroll time
  (an enroll may request a shorter TTL). Defaults to `720h`. Must be positive.
- `min_uid` — Unix-uid floor for any user the API may address or for whom a
  delegation may be enrolled; root and system accounts are rejected. Defaults to
  `1000`. Must not be negative.

The listener uses TLS 1.3 with `RequireAndVerifyClientCert`; there is no
anonymous or password fallback. Removing a CN from `gateway_cns` and reloading
the Agent immediately rejects that gateway's certificate.

### Certificate issuance

Issue a server certificate for the listener and a client certificate per
gateway, reusing the same private CA and the `dvault cert` workflow described in
the [Certificate lifecycle](#certificate-lifecycle) section below:

```bash
# HTTPS listener server certificate (CN = Agent host name).
sudo dvault cert issue --server \
  --ca-cert /etc/datavault/pki/ca.crt \
  --ca-key  /etc/datavault/pki/ca.key \
  --cert /etc/datavault/agent/https.crt \
  --key  /etc/datavault/agent/https.key \
  --common-name agent-01 --dns agent-01.example.com

# Gateway client certificate (CN = gateway identity, listed in gateway_cns).
sudo dvault cert issue --client \
  --ca-cert /etc/datavault/pki/ca.crt \
  --ca-key  /etc/datavault/pki/ca.key \
  --cert /etc/datavault/gateway/backup-web-01.crt \
  --key  /etc/datavault/gateway/backup-web-01.key \
  --common-name backup-web-01
```

Private keys are written with mode `0600`, certificates with mode `0644`.
Install the gateway's cert, key, and a copy of the CA certificate on the
gateway host through your secret-management process. Rotate certificates by
installing new files and restarting the affected services during a controlled
maintenance window.

### Gateway onboarding runbook

For each user the gateway will serve:

1. On the gateway, generate a per-user Ed25519 delegation key pair in
   SSH-compatible format and keep the private key under access control (see
   custody requirements below). Per-user keys give finer revocation than one
   shared gateway key and are the documented default.
2. Display the public key — an `authorized_keys`-format line such as
   `ssh-ed25519 AAAA... gateway-delegation:alice` — to the user, e.g. in the
   web UI. The gateway must never send the private key anywhere.
3. The user runs, on the Agent host with a live `SSH_AUTH_SOCK`:

   ```bash
   dvault web enroll --gateway backup-web-01 \
     --delegation-key 'ssh-ed25519 AAAA... gateway-delegation:alice' \
     --ttl 720h
   ```

   The `--delegation-key` flag accepts the key line directly or `@file` to read
   it from a file. The CLI signs with the user's SSH agent over the method,
   username, gateway CN, delegation public key, TTL, and a fresh nonce, so the
   key and CN cannot be swapped in flight.

4. Verify the enrollment succeeded with `dvault web list`, or by having the
   gateway read `GET /v1/users/alice/delegation`.

The user can later self-revoke with `dvault web revoke --gateway backup-web-01`,
or by asking the gateway to call `DELETE /v1/users/alice/delegation` on her
behalf. An operator can also remove the Server-side delegation key and the
local `web_delegations` row as an incident-response action.

### Firewall guidance

Bind `https_api.listen` to a private interface and restrict ingress to the
gateway subnet only, mirroring the Server's private-network policy. The HTTPS
API has no rate-limit bypass and no anonymous paths, but it is still an
authentication surface: do not place it on a public interface. If the gateway
and Agent share a VLAN or VPN, prefer that addressing.

### Delegation private-key custody

Each delegation private key is root-equivalent for the enrolled user's backup
authority until expiry or revocation: paired with the gateway client
certificate, it can trigger syncs, request restores, and read quota for that
user. Treat it with the same care as Agent private keys and user SSH private
keys:

- Store it on the gateway host with `0600` permissions, owned by the gateway
  service account, on encrypted storage where available.
- Do not commit it to source control, bake it into container images, or send it
  to the Agent — the gateway signs locally and only the public key ever leaves.
- Rotate delegation keys on the same cadence as gateway certificates, and after
  any personnel or host change with access to the gateway key store; rotation is
  a fresh `dvault web enroll` plus revocation of the previous delegation.
- Treat loss or suspected exposure of a delegation key as a compromise of that
  user's backup authority: revoke the delegation and review backups made under
  it.

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
