// Package transport implements the gRPC streaming client that pushes file
// diffs to the backup server. It handles batch construction, SSH agent
// signing for user-rule backups, and progress tracking.
package transport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/packager"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/scanner"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// PushConfig holds the parameters needed to run a backup push operation.
type PushConfig struct {
	Client   backuppbv1.BackupServiceClient
	Username string
	RuleType string // "user" or "machine"
	ServerID string
	Tracker  *progress.Tracker
	RootPath string // absolute base path used to read files from disk
}

// PushBackup sends file diffs to the server via a bidirectional gRPC stream.
//
// Flow:
//  1. Fetch a challenge nonce from the server (required for signing user batches).
//  2. Pack the diffs into batches of up to DefaultBatchSize files.
//  3. For each batch: read file contents from disk, build a BackupBatch proto,
//     optionally sign with SSH agent (user rules), send, and wait for ack.
//  4. Close the send side of the stream on completion.
func PushBackup(ctx context.Context, cfg PushConfig, diffs []scanner.FileDiff) error {
	// Step 1: Obtain a challenge nonce from the server.
	challenge, err := cfg.Client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
	if err != nil {
		return fmt.Errorf("get challenge: %w", err)
	}

	// Step 2: Partition diffs into fixed-size batches.
	batches := packager.PackBatches(diffs, packager.DefaultBatchSize)
	cfg.Tracker.SetTotals(int64(len(diffs)), int64(len(diffs)))
	cfg.Tracker.SetPhase(progress.PhaseTransferring)

	// Step 3: Open the bidirectional push stream.
	stream, err := cfg.Client.PushBackup(ctx)
	if err != nil {
		return fmt.Errorf("open push stream: %w", err)
	}

	// Step 4: Send each batch and process the server ack.
	for _, batch := range batches {
		cfg.Tracker.SetCurrentFiles(batchFilePaths(batch))

		if err := sendBatch(ctx, stream, cfg, batch, challenge.Nonce); err != nil {
			return fmt.Errorf("batch %s: %w", batch.ID, err)
		}
	}

	// Step 5: Close the send side so the server finalises the snapshot.
	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("close send: %w", err)
	}
	return nil
}

// sendBatch builds a BackupBatch proto from the packager batch, reads file
// contents from disk, signs the batch for user rules, sends it on the
// stream, and waits for the server acknowledgement.
func sendBatch(
	ctx context.Context,
	stream grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck],
	cfg PushConfig,
	batch packager.Batch,
	nonce []byte,
) error {
	pb := &backuppbv1.BackupBatch{
		BatchId:  batch.ID,
		Username: cfg.Username,
		RuleType: cfg.RuleType,
	}

	// Populate file entries -- read actual content from disk for add/modify.
	for _, d := range batch.Files {
		entry := &backuppbv1.FileEntry{
			Path:    d.File.Path,
			Mode:    d.File.Mode,
			Deleted: d.Action == scanner.DiffDelete,
		}
		if d.Action != scanner.DiffDelete {
			absPath := filepath.Join(cfg.RootPath, d.File.Path)
			data, err := os.ReadFile(absPath)
			if err != nil {
				// Skip files that cannot be read; the next sync will retry them.
				continue
			}
			entry.Content = data
		}
		pb.Files = append(pb.Files, entry)
	}

	// User-rule batches must carry an SSH signature over:
	//   nonce || "PushBackup" || sha256(marshalled batch without sig/nonce)
	if cfg.RuleType == "user" {
		if err := signBatch(pb, nonce); err != nil {
			return fmt.Errorf("sign: %w", err)
		}
	}

	// Send the batch.
	if err := stream.Send(pb); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	// Wait for server acknowledgement.
	ack, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv ack: %w", err)
	}
	if ack.Status != "OK" {
		return fmt.Errorf("server rejected: %s", ack.Error)
	}

	cfg.Tracker.AddTransferred(int64(len(pb.Files)), ack.WrittenBytes)
	return nil
}

// signBatch marshals the BackupBatch proto (which at this point has no
// Signature or Nonce fields set), computes its SHA-256, and signs the
// payload with the SSH agent. The resulting signature bytes and nonce are
// stored directly on the proto message.
func signBatch(pb *backuppbv1.BackupBatch, nonce []byte) error {
	// Hash the batch *before* attaching signature/nonce so the server can
	// recompute the same hash by clearing those fields on receipt.
	data, err := proto.Marshal(pb)
	if err != nil {
		return fmt.Errorf("marshal batch for hash: %w", err)
	}
	hash := sha256.Sum256(data)

	// Build signing payload: nonce || "PushBackup" || sha256(batch)
	sigData := make([]byte, 0, len(nonce)+len("PushBackup")+sha256.Size)
	sigData = append(sigData, nonce...)
	sigData = append(sigData, []byte("PushBackup")...)
	sigData = append(sigData, hash[:]...)

	_, sig, err := auth.SignWithSSHAgent(sigData)
	if err != nil {
		return fmt.Errorf("ssh-agent sign: %w", err)
	}

	pb.Signature = ssh.Marshal(sig)
	pb.Nonce = nonce
	return nil
}

// batchFilePaths extracts the relative file paths from a batch for display
// in the progress tracker.
func batchFilePaths(b packager.Batch) []string {
	paths := make([]string, len(b.Files))
	for i, f := range b.Files {
		paths[i] = f.File.Path
	}
	return paths
}
