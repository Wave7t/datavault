package orchestrator

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/progress"
	"google.golang.org/grpc"
)

func withHome(t *testing.T, home string) {
	old := lookupUserHome
	lookupUserHome = func(username string, uid uint32) (string, error) {
		return home, nil
	}
	t.Cleanup(func() { lookupUserHome = old })
}

func TestValidateRestoreTargetDefault(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)

	target, err := validateRestoreTarget("alice", uint32(os.Getuid()), "")
	if err != nil {
		t.Fatalf("validateRestoreTarget: %v", err)
	}
	if target != filepath.Join(home, "restored") {
		t.Fatalf("unexpected target %q", target)
	}
}

func TestValidateRestoreTargetRejectsOutsideHome(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)

	_, err := validateRestoreTarget("alice", uint32(os.Getuid()), filepath.Dir(home))
	if err == nil {
		t.Fatal("expected outside-home target to fail")
	}
}

func TestValidateRestoreTargetRejectsSymlink(t *testing.T) {
	home := t.TempDir()
	withHome(t, home)
	link := filepath.Join(home, "link")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}

	_, err := validateRestoreTarget("alice", uint32(os.Getuid()), link)
	if err == nil {
		t.Fatal("expected symlink target to fail")
	}
}

func TestRestoreFromStreamWritesThenRenames(t *testing.T) {
	target := filepath.Join(t.TempDir(), "restored")
	stream := &fakeRestoreStream{batches: []*backuppbv1.RestoreBatch{
		{Files: []*backuppbv1.FileEntry{{Path: "dir/a.txt", Content: []byte("alpha"), Mode: 0644}}},
		{IsLast: true},
	}}

	if err := restoreFromStream(stream, target, uint32(os.Getuid()), progress.NewTracker()); err != nil {
		t.Fatalf("restoreFromStream: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(target, "dir", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "alpha" {
		t.Fatalf("unexpected content %q", data)
	}
}

func TestWriteRestoredFileRejectsTraversal(t *testing.T) {
	err := writeRestoredFile(t.TempDir(), &backuppbv1.FileEntry{Path: "../evil", Content: []byte("x"), Mode: 0644})
	if err == nil {
		t.Fatal("expected traversal error")
	}
}

func TestRestoreFromStreamReassemblesChunks(t *testing.T) {
	target := filepath.Join(t.TempDir(), "restored")
	stream := &fakeRestoreStream{batches: []*backuppbv1.RestoreBatch{
		{Files: []*backuppbv1.FileEntry{{Path: "large.bin", Content: []byte("alpha"), Mode: 0600, Chunked: true, ChunkOffset: 0}}},
		{Files: []*backuppbv1.FileEntry{{Path: "large.bin", Content: []byte("beta"), Mode: 0600, Chunked: true, ChunkOffset: 5, FinalChunk: true}}},
		{IsLast: true},
	}}
	if err := restoreFromStream(stream, target, uint32(os.Getuid()), progress.NewTracker()); err != nil {
		t.Fatalf("restoreFromStream: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(target, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "alphabeta" {
		t.Fatalf("chunked restore content=%q", data)
	}
}

type fakeRestoreStream struct {
	grpc.ServerStreamingClient[backuppbv1.RestoreBatch]
	batches []*backuppbv1.RestoreBatch
	idx     int
}

func (s *fakeRestoreStream) Recv() (*backuppbv1.RestoreBatch, error) {
	if s.idx >= len(s.batches) {
		return nil, io.EOF
	}
	batch := s.batches[s.idx]
	s.idx++
	return batch, nil
}

func (s *fakeRestoreStream) Context() context.Context { return context.Background() }
