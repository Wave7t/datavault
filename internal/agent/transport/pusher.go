package transport

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/packager"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/scanner"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const chunkContentBytes = 4 * 1024 * 1024

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
	// BandwidthLimitBytesPerSecond limits upload payloads for this attempt.
	// Zero leaves transfers unlimited.
	BandwidthLimitBytesPerSecond int64
}

type bandwidthLimiter struct {
	rate  int64
	now   func() time.Time
	sleep func(time.Duration)
	next  time.Time
}

func newBandwidthLimiter(rate int64, now func() time.Time, sleep func(time.Duration)) *bandwidthLimiter {
	if rate <= 0 {
		return nil
	}
	return &bandwidthLimiter{rate: rate, now: now, sleep: sleep}
}

func (l *bandwidthLimiter) wait(bytes int) {
	if l == nil || bytes <= 0 {
		return
	}
	now := l.now()
	if l.next.Before(now) {
		l.next = now
	}
	duration := time.Duration((int64(bytes)*int64(time.Second) + l.rate - 1) / l.rate)
	l.next = l.next.Add(duration)
	if delay := l.next.Sub(now); delay > 0 {
		l.sleep(delay)
	}
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
	limiter := newBandwidthLimiter(cfg.BandwidthLimitBytesPerSecond, time.Now, time.Sleep)

	for _, batch := range batches {
		if cfg.Tracker != nil {
			cfg.Tracker.SetCurrentFiles(batchFilePaths(batch))
		}
		if isLargeFileBatch(batch) {
			if err := sendChunkedFile(stream, cfg, batch.ID, batch.Files[0], nonce, limiter); err != nil {
				return fmt.Errorf("batch %s: %w", batch.ID, err)
			}
			continue
		}
		if err := sendBatch(stream, cfg, batch, nonce, limiter); err != nil {
			return fmt.Errorf("batch %s: %w", batch.ID, err)
		}
	}

	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("close send: %w", err)
	}
	// The server creates the recovery snapshot only after it receives EOF. A
	// successful CloseSend only means the request half was closed; read the
	// terminal result so a snapshot/retention failure cannot be reported as a
	// successful backup.
	if _, err := stream.Recv(); err != io.EOF {
		return fmt.Errorf("complete backup stream: %w", err)
	}
	return nil
}

func isLargeFileBatch(batch packager.Batch) bool {
	return len(batch.Files) == 1 && batch.Files[0].Action != scanner.DiffDelete && batch.Files[0].File.Size > packager.MaxBatchContentBytes
}

func sendChunkedFile(
	stream grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck],
	cfg PushConfig,
	batchID string,
	diff scanner.FileDiff,
	nonce []byte,
	limiter *bandwidthLimiter,
) error {
	localPath, err := sourcePath(cfg.PathPrefix, diff.File.Path)
	if err != nil {
		return err
	}
	path := filepath.Join(cfg.RootPath, localPath)
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()

	buf := make([]byte, chunkContentBytes)
	var offset int64
	for offset < diff.File.Size {
		want := int64(len(buf))
		if remaining := diff.File.Size - offset; remaining < want {
			want = remaining
		}
		n, readErr := io.ReadFull(file, buf[:want])
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return fmt.Errorf("read %q: %w", path, readErr)
		}
		if n == 0 {
			return fmt.Errorf("read %q: file changed while preparing chunks", path)
		}
		if readErr != nil && offset+int64(n) != diff.File.Size {
			return fmt.Errorf("read %q: file changed while preparing chunks", path)
		}
		final := offset+int64(n) == diff.File.Size
		pb := &backuppbv1.BackupBatch{
			BatchId:  fmt.Sprintf("%s-chunk-%d", batchID, offset/int64(chunkContentBytes)+1),
			Username: cfg.Username,
			RuleType: cfg.RuleType,
			Files: []*backuppbv1.FileEntry{{
				Path:        diff.File.Path,
				Content:     append([]byte(nil), buf[:n]...),
				Mode:        diff.File.Mode,
				Chunked:     true,
				ChunkOffset: uint64(offset),
				FinalChunk:  final,
			}},
		}
		if cfg.RuleType == "user" {
			if err := signBatch(pb, nonce, cfg.SignFunc); err != nil {
				return fmt.Errorf("sign: %w", err)
			}
		}
		limiter.wait(len(pb.Files[0].Content))
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
			files := int64(0)
			if final {
				files = 1
			}
			cfg.Tracker.AddTransferred(files, ack.WrittenBytes)
		}
		offset += int64(n)
	}
	return nil
}

func sendBatch(
	stream grpc.BidiStreamingClient[backuppbv1.BackupBatch, backuppbv1.BatchAck],
	cfg PushConfig,
	batch packager.Batch,
	nonce []byte,
	limiter *bandwidthLimiter,
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
	var payloadBytes int
	for _, entry := range pb.Files {
		payloadBytes += len(entry.Content)
	}
	limiter.wait(payloadBytes)

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
