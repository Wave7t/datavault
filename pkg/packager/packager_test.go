package packager

import (
	"fmt"
	"testing"

	"github.com/example/datavault/pkg/scanner"
)

func TestPackBatches(t *testing.T) {
	diffs := make([]scanner.FileDiff, 2500)
	for i := range diffs {
		diffs[i] = scanner.FileDiff{
			File:   scanner.FileInfo{Path: fmt.Sprintf("file-%d", i)},
			Action: scanner.DiffAdd,
		}
	}

	batches := PackBatches(diffs, 1000)
	if len(batches) != 3 {
		t.Fatalf("expected 3 batches, got %d", len(batches))
	}
	if len(batches[0].Files) != 1000 {
		t.Fatalf("batch 0: expected 1000, got %d", len(batches[0].Files))
	}
	if len(batches[1].Files) != 1000 {
		t.Fatalf("batch 1: expected 1000, got %d", len(batches[1].Files))
	}
	if len(batches[2].Files) != 500 {
		t.Fatalf("batch 2: expected 500, got %d", len(batches[2].Files))
	}
}

func TestPackBatchesEmpty(t *testing.T) {
	batches := PackBatches(nil, 1000)
	if len(batches) != 0 {
		t.Fatalf("expected 0 batches, got %d", len(batches))
	}
}

func TestPackBatchesSmallerThanSize(t *testing.T) {
	diffs := []scanner.FileDiff{{Action: scanner.DiffAdd}}
	batches := PackBatches(diffs, 1000)
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
}

func TestPackBatchesDefaultSize(t *testing.T) {
	diffs := make([]scanner.FileDiff, 100)
	batches := PackBatches(diffs, 0) // default 1000
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch with default size, got %d", len(batches))
	}
}

func TestPackBatchesWithinSize(t *testing.T) {
	diffs := []scanner.FileDiff{
		{File: scanner.FileInfo{Path: "one", Size: 8}},
		{File: scanner.FileInfo{Path: "two", Size: 8}},
		{File: scanner.FileInfo{Path: "three", Size: 2}},
	}
	batches, err := PackBatchesWithinSize(diffs, DefaultBatchSize, 10)
	if err != nil {
		t.Fatalf("PackBatchesWithinSize: %v", err)
	}
	if len(batches) != 2 || len(batches[0].Files) != 1 || len(batches[1].Files) != 2 {
		t.Fatalf("unexpected batches: %#v", batches)
	}
}

func TestPackBatchesWithinSizeKeepsOversizedFileStandalone(t *testing.T) {
	batches, err := PackBatchesWithinSize([]scanner.FileDiff{{File: scanner.FileInfo{Path: "large", Size: 11}}}, DefaultBatchSize, 10)
	if err != nil {
		t.Fatalf("PackBatchesWithinSize: %v", err)
	}
	if len(batches) != 1 || len(batches[0].Files) != 1 || batches[0].Files[0].File.Path != "large" {
		t.Fatalf("expected one standalone oversized batch, got %#v", batches)
	}
}
