# Server formal-test preflight

Use this checklist after the local build and unit-test suite succeeds, before
connecting an Agent to a real ZFS-backed server.

## Required configuration

- Set `agent.ca_file` and `server.ca_file` to the PEM bundle that issued both
  the Agent and Server certificates. Startup now fails when the configured CA
  bundle is empty, unreadable, or contains no certificate.
- Ensure the server certificate has a DNS/IP SAN matching the hostname the
  Agent verifies (normally `servers[].address`, or `tls_server_name` when set).
- Install each client public key as
  `/etc/datavault/server/authorized_keys/<hostname>/<username>.pub`.
- If `backup_pool` does not mount at `/tank/backups`, update
  `ReadWritePaths` in `scripts/datavault-server.service` before enabling it.
- Configure only absolute user paths inside the owning user's home directory.
  Backups restore the source-root hierarchy below the requested restore target.
- Run `dvault sync trigger` with the invoking user's `SSH_AUTH_SOCK` set. The
  Agent verifies that this Unix socket is owned by the authenticated local peer
  before it requests per-batch signatures.
- Issue the CA and service certificates with `dvault cert init-ca` and
  `dvault cert issue`; private keys must remain mode `0600`. Probe the
  mTLS-protected standard gRPC health service before admitting traffic.
- Ensure each Agent `servers[].address` matches a server certificate DNS/IP
  SAN. When transport routing uses a load-balancer alias, container name, or
  IP that does not match the certificate, set `servers[].tls_server_name` to
  the certificate SAN; this preserves normal hostname verification.
- Configure absolute hook paths and `quota_warning_percent` when operational
  notifications are required. `schedule_window` limits cron-triggered machine
  rules to a local-time range and supports overnight windows.
- Include at least one file larger than 16 MiB. Verify its upload and restore
  checksum: the transport must send bounded ordered chunks and the server must
  expose the file only after the final chunk commits atomically.

## Formal server test matrix

1. Start the service with its real CA, ZFS pool, and an allowed Agent
   certificate. Confirm that a connection without a client certificate, with
   the wrong CA, and with a non-allowed CN is rejected.
2. Run a machine-rule backup. Verify it writes only to
   `<pool>/<hostname>/_machine/`, creates a snapshot, and retains the expected
   snapshot count.
3. Attempt machine uploads with a non-`_machine` username, `_machine` as a
   user rule, and an unknown rule type. Each must be rejected.
4. Exercise a signed quota request and restore request, then replay the same
   nonce. The first request should succeed and the replay should be rejected.
5. Back up two separate roots containing the same relative filename. Verify
   both files exist under their distinct source-root prefixes after restore.
   Also change only a file's mode and verify the restored mode changes.
6. Back up and restore a file larger than 16 MiB. Compare checksums before
   upload and after restore, then interrupt a chunked upload and verify no
   partial file becomes visible in the target dataset.
7. Simulate an unreadable or missing path during a scan. Confirm the Agent
   marks the task failed and does not send deletion markers for that root.
8. Validate quota enforcement with a controlled over-quota upload and verify
   that failed transfers do not advance the local snapshot database.
9. Restart both services, then repeat an incremental upload, a deletion, and a
   restore to ensure SQLite state, ZFS datasets, and nonce state survive
   restart.

## Remaining deployment responsibilities

- A restore uses the configured server that issued its nonce. If it fails
  after signing, request a fresh challenge from another replica and retry the
  restore; transparent mid-stream failover needs multiple server-specific
  signatures.
- Exercise real disks, ZFS topology, power-loss recovery, monitoring, and
  alert delivery before production admission.

## Validated application-level baseline

The loop-backed ZFS validation run covers the application protocol and its
filesystem integration without requiring access to a physical ZFS host. Its
passing baseline includes mTLS health checks, machine backup updates and
deletions, task failure persistence, signed user backup and restore, and
rejection of replayed quota and restore nonces.

This is evidence that the service is ready to enter a production admission
process, not evidence that a specific storage deployment is production-ready.
Run the remaining deployment responsibilities above against the intended
disks, pool topology, monitoring, and incident-response paths before serving
production data.
