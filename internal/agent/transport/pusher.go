package transport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/packager"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/scanner"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type PushConfig struct {
	Client   backuppbv1.BackupServiceClient
	Username string
	RuleType string
	ServerID string
	Tracker  *progress.Tracker
	RootPath string
	// PathPrefix is prepended to each source-relative path in the archive.
	// It is stripped again when reading source file contents locally.
	PathPrefix string
	SignFunc   func([]byte) ([]byte, *ssh.Signature, error)
}

func PushBackup(ctx context.Context, cfg PushConfig, diffs []scanner.FileDiff) error {
	if len(diffs) == 0 {
		return nil
	}
	if err := validatePushConfig(cfg); err != nil {
		return err
	}
	batches, err := packager.PackBatchesWithinSize(diffs, packager.DefaultBatchSize, packager.MaxBatchContentBytes)
	if err != nil {
		return fmt.Errorf("pack batches: %w", err)
	}

	var nonce []byte
	if cfg.RuleType == "user" {
		challenge, err := cfg.Client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
		if err != nil {
			return fmt.Errorf("get challenge: %w", err)
		}
		nonce = challenge.Nonce
	}

	stream, err := cfg.Client.PushBackup(ctx)
	if err != nil {
		return fmt.Errorf("open push stream: %w", err)
	}

	if cfg.Tracker != nil {
		cfg.Tracker.SetTotals(int64(len(diffs)), int64(len(diffs)))
		cfg.Tracker.SetPhase(progress.PhaseTransferring)
	}

	for _, batch := range batches {
		if cfg.Tracker != nil {
			cfg.Tracker.SetCurrentFiles(batchFilePaths(batch))
		}
		if err := sendBatch(stream, cfg, batch, nonce); err != nil {
			return fmt.Errorf("batch %s: %w", batch.ID, err)
		}
	}

	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("close send: %w", err)
	}
	return nil
}

func sendBatch(
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

	for _, diff := range batch.Files {
		entry := &backuppbv1.FileEntry{
			Path:    diff.File.Path,
			Mode:    diff.File.Mode,
			Deleted: diff.Action == scanner.DiffDelete,
		}
		if diff.Action != scanner.DiffDelete {
			localPath, err := sourcePath(cfg.PathPrefix, diff.File.Path)
			if err != nil {
				return err
			}
			absPath := filepath.Join(cfg.RootPath, localPath)
			data, err := os.ReadFile(absPath)
			if err != nil {
				return fmt.Errorf("read %q: %w", absPath, err)
			}
			entry.Content = data
		}
		pb.Files = append(pb.Files, entry)
	}

	if cfg.RuleType == "user" {
		if err := signBatch(pb, nonce, cfg.SignFunc); err != nil {
			return fmt.Errorf("sign: %w", err)
		}
	}

	if err := stream.Send(pb); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	ack, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv ack: %w", err)
	}
	if ack.Status != "OK" {
		return fmt.Errorf("server rejected: %s", ack.Error)
	}

	if cfg.Tracker != nil {
		cfg.Tracker.AddTransferred(int64(len(pb.Files)), ack.WrittenBytes)
	}
	return nil
}

func validatePushConfig(cfg PushConfig) error {
	switch cfg.RuleType {
	case "user":
		if cfg.Username == "_machine" {
			return fmt.Errorf("_machine backups must use rule type machine")
		}
	case "machine":
		if cfg.Username != "_machine" {
			return fmt.Errorf("machine backups must use username _machine")
		}
	default:
		return fmt.Errorf("invalid backup rule type %q", cfg.RuleType)
	}
	return nil
}

func sourcePath(prefix, archivePath string) (string, error) {
	cleanPath := filepath.Clean(archivePath)
	if prefix == "" {
		return cleanPath, nil
	}
	cleanPrefix := filepath.Clean(prefix)
	if cleanPath == cleanPrefix || !strings.HasPrefix(cleanPath, cleanPrefix+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path %q is outside root prefix %q", archivePath, prefix)
	}
	return strings.TrimPrefix(cleanPath, cleanPrefix+string(filepath.Separator)), nil
}

func signBatch(pb *backuppbv1.BackupBatch, nonce []byte, signFunc func([]byte) ([]byte, *ssh.Signature, error)) error {
	data, err := proto.Marshal(pb)
	if err != nil {
		return fmt.Errorf("marshal batch for hash: %w", err)
	}
	hash := sha256.Sum256(data)

	payload := make([]byte, 0, len(nonce)+len("PushBackup")+sha256.Size)
	payload = append(payload, nonce...)
	payload = append(payload, []byte("PushBackup")...)
	payload = append(payload, hash[:]...)

	if signFunc == nil {
		signFunc = auth.SignWithSSHAgent
	}

	_, sig, err := signFunc(payload)
	if err != nil {
		return fmt.Errorf("ssh-agent sign: %w", err)
	}

	pb.Signature = ssh.Marshal(sig)
	pb.Nonce = nonce
	return nil
}

func batchFilePaths(b packager.Batch) []string {
	paths := make([]string, len(b.Files))
	for i, f := range b.Files {
		paths[i] = f.File.Path
	}
	return paths
}
