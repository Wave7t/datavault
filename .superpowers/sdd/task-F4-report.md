# Task F4 Report: Transport Layer (PushBackup Client)

**Status:** Complete
**File:** `internal/agent/transport/pusher.go`
**Build:** `go build ./internal/agent/transport/` -- PASS

## What was implemented

Created the PushBackup streaming gRPC client in `internal/agent/transport/pusher.go`. The package exports:

- `PushConfig` struct -- holds the gRPC client, username, rule type, server ID, progress tracker, and a `RootPath` for resolving relative scanned paths to absolute disk paths.
- `PushBackup(ctx, cfg, diffs)` function -- the main entry point.
- `batchFilePaths(batch)` helper -- extracts file paths from a packager.Batch for progress display.

## Implementation details

### Flow

1. **Fetch challenge nonce** from the server via `GetChallenge`.
2. **Pack diffs** into batches using `packager.PackBatches` (1000 files/batch).
3. **Open bidirectional stream** via `client.PushBackup(ctx)`.
4. **For each batch:**
   - Read file contents from disk (`os.ReadFile(filepath.Join(cfg.RootPath, d.File.Path))`).
   - Build `BackupBatch` proto with `FileEntry` records.
   - Skip files that cannot be read (they will be retried next sync).
   - For `ruleType == "user"`: sign the batch with SSH agent.
   - Send batch, receive `BatchAck`, update progress tracker.
5. **Close send side** of stream so server finalizes the snapshot.

### Signing protocol

For user-rule batches, the signature is computed as:
```
sigData = nonce || "PushBackup" || sha256(proto.Marshal(batch_without_sig_or_nonce))
```

- The batch is marshaled **before** attaching `Signature` and `Nonce` fields to avoid a circular hash dependency.
- `auth.SignWithSSHAgent` returns `([]byte, *ssh.Signature, error)`.
- The signature is serialized via `ssh.Marshal(sig)` for the `bytes signature` proto field.

### File reading

The plan code was incomplete for file reading. The scanner stores **relative** paths in `FileInfo.Path`. The pusher accepts a `RootPath` in `PushConfig` (provided by the orchestrator) and resolves absolute paths via `filepath.Join(cfg.RootPath, d.File.Path)` before calling `os.ReadFile`.

## Deviations from the plan

| Plan | Implementation |
|------|---------------|
| `pb.Signature = sig` (wrong type) | `pb.Signature = ssh.Marshal(sig)` |
| Inline `hashBatch(pb)` helper | Inlined in `signBatch(pb, nonce)` |
| Unused `metadata` import | Removed |
| `d.File.Path` used directly for `os.ReadFile` (relative path) | `filepath.Join(cfg.RootPath, d.File.Path)` for absolute path resolution |
| Added `RootPath` field to `PushConfig` | Required for disk file reading |
| `cfg.Tracker.SetPhase(progress.PhaseTransferring)` | Added phase tracking |
| `pb.Signature = sig` needed proper marshaling (noted in plan) | Resolved with `ssh.Marshal` |

## Known issue: Server-side hash mismatch

The server (`internal/server/svc/backup.go`) computes the batch hash via `sha256.Sum256(mustMarshal(batch))` where `batch` has already been received from the stream with `Signature` and `Nonce` fields populated. This means the server marshals a different byte sequence than what the client used for signing (client marshals without sig/nonce).

This is a pre-existing bug in the server code that will cause signature verification to fail. The server should clear `Signature`/`Nonce` fields (or clone the message) before marshaling for the hash. This needs to be addressed in a follow-up fix to the server.
