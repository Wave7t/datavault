# Server formal-test preflight

Use this checklist after the local build and unit-test suite succeeds, before
connecting an Agent to a real ZFS-backed server.

## Required configuration

- Set `agent.ca_file` and `server.ca_file` to the PEM bundle that issued both
  the Agent and Server certificates. Startup now fails when the configured CA
  bundle is empty, unreadable, or contains no certificate.
- Ensure the server certificate has a DNS/IP SAN matching each configured
  `servers[].address`; the Agent verifies the server certificate.
- Install each client public key as
  `/etc/datavault/server/authorized_keys/<hostname>/<username>.pub`.
- If `backup_pool` does not mount at `/tank/backups`, update
  `ReadWritePaths` in `scripts/datavault-server.service` before enabling it.
- Configure only absolute user paths inside the owning user's home directory.
  Backups restore the source-root hierarchy below the requested restore target.
- Do not include a single file over 15 MiB in this test round. The current
  FileEntry protocol has no chunking support; batches are otherwise kept under
  the 16 MiB gRPC message limit.

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
6. Simulate an unreadable path during a scan. Confirm the Agent reports a
   failed/skipped root and does not send deletion markers for that root.
7. Validate quota enforcement with a controlled over-quota upload and verify
   that failed transfers do not advance the local snapshot database.
8. Restart both services, then repeat an incremental upload, a deletion, and a
   restore to ensure SQLite state, ZFS datasets, and nonce state survive
   restart.

## Known release blockers

- User backup batch signing is still performed by the root-run Agent, while
  the design requires each batch to be signed by the invoking CLI user's SSH
  agent. A bidirectional CLI-to-Agent signing protocol is required before
  treating user backup sync as production-ready. Quota and restore already use
  CLI-side signing and may be exercised in the formal test.
- Restore uses only the first configured server. Automatic server failover,
  retry classification, hooks, bandwidth limiting, and scheduler time-window
  enforcement remain outside this preflight scope.
