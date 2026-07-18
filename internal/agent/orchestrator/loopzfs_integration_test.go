package orchestrator

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/datavault/internal/agent/pool"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
)

func TestLoopZFSMachineOrchestratorTracksModesAndDeletes(t *testing.T) {
	certDir := os.Getenv("DVAULT_LOOPZFS_AGENT_CERT_DIR")
	serverAddr := os.Getenv("DVAULT_LOOPZFS_ADDR")
	dataDir := os.Getenv("DVAULT_LOOPZFS_DATA_DIR")
	if certDir == "" || serverAddr == "" || dataDir == "" {
		t.Skip("set DVAULT_LOOPZFS_AGENT_CERT_DIR, DVAULT_LOOPZFS_ADDR, and DVAULT_LOOPZFS_DATA_DIR")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatalf("create source root: %v", err)
	}
	path := filepath.Join(dataDir, "orchestrator.txt")
	if err := os.WriteFile(path, []byte("first revision"), 0600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	db, err := store.OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state database: %v", err)
	}
	defer db.Close()
	if err := store.MigrateSnapshots(db); err != nil {
		t.Fatalf("migrate snapshots: %v", err)
	}
	if err := store.MigrateTasks(db); err != nil {
		t.Fatalf("migrate tasks: %v", err)
	}

	connections, err := pool.New(
		filepath.Join(certDir, "agent.crt"),
		filepath.Join(certDir, "agent.key"),
		filepath.Join(certDir, "ca.crt"),
	)
	if err != nil {
		t.Fatalf("create mTLS connection pool: %v", err)
	}
	defer connections.Close()

	cfg := &config.AgentConfig{
		Servers: []config.ServerEntry{{Address: serverAddr, TLSServerName: "server"}},
		MachineRules: []config.MachineRule{{
			Name:     "loop-zfs",
			Paths:    []string{dataDir},
			Enabled:  true,
			Schedule: "0 0 * * *",
		}},
	}
	orch := New(cfg, connections, db, rules.NewUserRuleStore(t.TempDir()))

	runLoopZFSSync(t, orch, db)
	archivedPath := filepath.ToSlash(filepath.Join(filepath.Base(dataDir), "orchestrator.txt"))
	assertLoopZFSSnapshot(t, db, serverAddr, archivedPath, 0600)

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("change source mode: %v", err)
	}
	runLoopZFSSync(t, orch, db)
	assertLoopZFSSnapshot(t, db, serverAddr, archivedPath, 0644)

	if err := os.Remove(path); err != nil {
		t.Fatalf("delete source file: %v", err)
	}
	runLoopZFSSync(t, orch, db)
	snapshot, err := store.GetSnapshot(db, serverAddr, machineUsername, archivedPath)
	if err != nil {
		t.Fatalf("get deleted snapshot state: %v", err)
	}
	if snapshot != nil {
		t.Fatalf("deleted file remains in local snapshot state: %#v", snapshot)
	}
}

func TestLoopZFSMachineOrchestratorFailsMissingRoot(t *testing.T) {
	certDir := os.Getenv("DVAULT_LOOPZFS_AGENT_CERT_DIR")
	serverAddr := os.Getenv("DVAULT_LOOPZFS_ADDR")
	dataDir := os.Getenv("DVAULT_LOOPZFS_DATA_DIR")
	if certDir == "" || serverAddr == "" || dataDir == "" {
		t.Skip("set DVAULT_LOOPZFS_AGENT_CERT_DIR, DVAULT_LOOPZFS_ADDR, and DVAULT_LOOPZFS_DATA_DIR")
	}

	db, err := store.OpenDB(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.MigrateSnapshots(db); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateTasks(db); err != nil {
		t.Fatal(err)
	}
	connections, err := pool.New(
		filepath.Join(certDir, "agent.crt"),
		filepath.Join(certDir, "agent.key"),
		filepath.Join(certDir, "ca.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer connections.Close()

	orch := New(&config.AgentConfig{
		Servers: []config.ServerEntry{{Address: serverAddr, TLSServerName: "server"}},
		MachineRules: []config.MachineRule{{
			Name:     "missing-root",
			Paths:    []string{filepath.Join(dataDir, "does-not-exist")},
			Enabled:  true,
			Schedule: "0 0 * * *",
		}},
	}, connections, db, rules.NewUserRuleStore(t.TempDir()))
	taskID, err := orch.RunSync(machineUsername, "missing-root")
	if err != nil {
		t.Fatalf("RunSync: %v", err)
	}
	tracker, err := orch.GetTracker(taskID)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if phase, _, _ := tracker.Snapshot(); phase == progress.PhaseFailed {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("missing source root was not reported as a failed task")
}

func runLoopZFSSync(t *testing.T, orch *Orchestrator, db *sql.DB) {
	t.Helper()
	taskID, err := orch.RunSync(machineUsername, "loop-zfs")
	if err != nil {
		t.Fatalf("run machine sync: %v", err)
	}
	tracker, err := orch.GetTracker(taskID)
	if err != nil {
		t.Fatalf("get sync tracker: %v", err)
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		phase, _, _ := tracker.Snapshot()
		switch phase {
		case progress.PhaseCompleted:
			return
		case progress.PhaseFailed:
			task, err := store.GetTask(db, taskID)
			if err != nil {
				t.Fatalf("get failed task: %v", err)
			}
			if task == nil {
				t.Fatal("machine sync entered FAILED phase without a persisted task")
			}
			t.Fatalf("machine sync entered FAILED phase: %s", task.Error)
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("machine sync did not reach a terminal phase")
}

func assertLoopZFSSnapshot(t *testing.T, db *sql.DB, serverAddr, archivedPath string, mode uint32) {
	t.Helper()
	snapshot, err := store.GetSnapshot(db, serverAddr, machineUsername, archivedPath)
	if err != nil {
		t.Fatalf("get local snapshot state: %v", err)
	}
	if snapshot == nil {
		t.Fatalf("missing local snapshot for %q", archivedPath)
	}
	if snapshot.Mode != mode {
		t.Fatalf("local snapshot mode = %#o, want %#o", snapshot.Mode, mode)
	}
}
