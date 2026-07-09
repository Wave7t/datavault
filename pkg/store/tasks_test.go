package store

import "testing"

func TestInsertAndGetTask(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateTasks(db)

	tr := TaskRecord{TaskID: "task-1", ServerID: "srv", Username: "alice"}
	if err := InsertTask(db, tr); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := GetTask(db, "task-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected task, got nil")
	}
	if got.Phase != "PENDING" {
		t.Fatalf("expected PENDING, got %q", got.Phase)
	}
	if got.StartedAt == 0 {
		t.Fatal("expected started_at to be set")
	}
}

func TestUpdateTaskPhaseCompleted(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateTasks(db)

	InsertTask(db, TaskRecord{TaskID: "task-2", ServerID: "srv", Username: "bob"})
	if err := UpdateTaskPhase(db, "task-2", "COMPLETED", `{"files":100}`); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, _ := GetTask(db, "task-2")
	if got.Phase != "COMPLETED" {
		t.Fatalf("expected COMPLETED, got %q", got.Phase)
	}
	if got.EndedAt == 0 {
		t.Fatal("expected ended_at to be set for COMPLETED")
	}
	if got.StatsJSON != `{"files":100}` {
		t.Fatalf("expected stats_json, got %q", got.StatsJSON)
	}
}

func TestUpdateTaskPhaseFailed(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateTasks(db)

	InsertTask(db, TaskRecord{TaskID: "task-3", ServerID: "srv", Username: "bob"})
	if err := UpdateTaskPhase(db, "task-3", "FAILED", ""); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, _ := GetTask(db, "task-3")
	if got.Phase != "FAILED" {
		t.Fatalf("expected FAILED, got %q", got.Phase)
	}
	if got.EndedAt == 0 {
		t.Fatal("expected ended_at to be set for FAILED")
	}
}

func TestUpdateTaskPhaseRunning(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateTasks(db)

	InsertTask(db, TaskRecord{TaskID: "task-4", ServerID: "srv", Username: "alice"})
	if err := UpdateTaskPhase(db, "task-4", "SCANNING", ""); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, _ := GetTask(db, "task-4")
	if got.Phase != "SCANNING" {
		t.Fatalf("expected SCANNING, got %q", got.Phase)
	}
	if got.EndedAt != 0 {
		t.Fatal("expected ended_at to remain 0 for non-terminal phase")
	}
}

func TestGetTaskNotFound(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateTasks(db)

	got, err := GetTask(db, "nonexistent")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for nonexistent task")
	}
}
