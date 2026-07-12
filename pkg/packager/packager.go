// Package packager splits a diff result into fixed-size batches for
// streaming transmission over gRPC. Each batch holds up to
// DefaultBatchSize (1000) file entries.
package packager

import (
	"fmt"

	"github.com/example/datavault/pkg/scanner"
)

const DefaultBatchSize = 1000

// MaxBatchContentBytes leaves room for protobuf framing under the 16 MiB gRPC
// receive limit configured by the server and agent connection pool.
const MaxBatchContentBytes int64 = 15 * 1024 * 1024

// Batch groups a slice of file diffs under a unique identifier.
type Batch struct {
	ID    string
	Files []scanner.FileDiff
}

// PackBatches splits a list of file diffs into fixed-size batches.
// If batchSize <= 0 the DefaultBatchSize (1000) is used.
func PackBatches(diffs []scanner.FileDiff, batchSize int) []Batch {
	batches, err := PackBatchesWithinSize(diffs, batchSize, 0)
	if err != nil {
		return nil
	}
	return batches
}

// PackBatchesWithinSize splits files by both count and total file content.
// A non-positive maxBytes disables the byte limit. A single file that exceeds
// a positive limit cannot be represented by the current FileEntry protocol
// and returns an error before any stream is opened.
func PackBatchesWithinSize(diffs []scanner.FileDiff, batchSize int, maxBytes int64) ([]Batch, error) {
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}

	var batches []Batch
	var batchFiles []scanner.FileDiff
	var batchBytes int64
	flush := func() {
		if len(batchFiles) == 0 {
			return
		}
		batches = append(batches, Batch{
			ID:    fmt.Sprintf("batch-%d", len(batches)+1),
			Files: batchFiles,
		})
		batchFiles = nil
		batchBytes = 0
	}

	for _, diff := range diffs {
		fileBytes := int64(0)
		if diff.Action != scanner.DiffDelete {
			fileBytes = diff.File.Size
			if maxBytes > 0 && fileBytes > maxBytes {
				return nil, fmt.Errorf("file %q is %d bytes, exceeding the %d-byte batch limit", diff.File.Path, fileBytes, maxBytes)
			}
		}
		if len(batchFiles) > 0 && (len(batchFiles) >= batchSize || (maxBytes > 0 && batchBytes+fileBytes > maxBytes)) {
			flush()
		}
		batchFiles = append(batchFiles, diff)
		batchBytes += fileBytes
	}
	flush()
	return batches, nil
}
