// Package packager splits a diff result into fixed-size batches for
// streaming transmission over gRPC. Each batch holds up to
// DefaultBatchSize (1000) file entries.
package packager

import (
	"fmt"

	"github.com/example/datavault/pkg/scanner"
)

const DefaultBatchSize = 1000

// Batch groups a slice of file diffs under a unique identifier.
type Batch struct {
	ID    string
	Files []scanner.FileDiff
}

// PackBatches splits a list of file diffs into fixed-size batches.
// If batchSize <= 0 the DefaultBatchSize (1000) is used.
func PackBatches(diffs []scanner.FileDiff, batchSize int) []Batch {
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}

	var batches []Batch
	for i := 0; i < len(diffs); i += batchSize {
		end := i + batchSize
		if end > len(diffs) {
			end = len(diffs)
		}
		batches = append(batches, Batch{
			ID:    fmt.Sprintf("batch-%d", len(batches)+1),
			Files: diffs[i:end],
		})
	}
	return batches
}
