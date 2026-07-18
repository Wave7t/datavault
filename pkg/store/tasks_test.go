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

func TestUpdateTaskFailureStoresReason(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	if err := MigrateTasks(db); err != nil {
		t.Fatal(err)
	}
	if err := InsertTask(db, TaskRecord{TaskID: "task-failure", ServerID: "srv", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := UpdateTaskFailure(db, "task-failure", "server unavailable after retries"); err != nil {
		t.Fatal(err)
	}
	task, err := GetTask(db, "task-failure")
	if err != nil || task == nil {
		t.Fatalf("GetTask: task=%#v err=%v", task, err)
	}
	if task.Phase != "FAILED" || task.Error != "server unavailable after retries" || task.EndedAt == 0 {
		t.Fatalf("unexpected failed task: %#v", task)
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

func TestGetLatestTaskForUser(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	if err := MigrateTasks(db); err != nil {
		t.Fatal(err)
	}
	if err := InsertTask(db, TaskRecord{TaskID: "alice-1", ServerID: "server", Username: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertTask(db, TaskRecord{TaskID: "bob-1", ServerID: "server", Username: "bob"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertTask(db, TaskRecord{TaskID: "alice-2", ServerID: "server", Username: "alice"}); err != nil {
		t.Fatal(err)
	}

	task, err := GetLatestTaskForUser(db, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if task == nil || task.TaskID != "alice-2" {
		t.Fatalf("latest task = %#v, want alice-2", task)
	}
}

func TestFailIncompleteTasks(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	if err := MigrateTasks(db); err != nil {
		t.Fatal(err)
	}
	for _, task := range []TaskRecord{
		{TaskID: "pending", ServerID: "server", Username: "alice"},
		{TaskID: "scanning", ServerID: "server", Username: "alice"},
		{TaskID: "complete", ServerID: "server", Username: "alice"},
	} {
		if err := InsertTask(db, task); err != nil {
			t.Fatal(err)
		}
	}
	if err := UpdateTaskPhase(db, "scanning", "SCANNING", ""); err != nil {
		t.Fatal(err)
	}
	if err := UpdateTaskPhase(db, "complete", "COMPLETED", ""); err != nil {
		t.Fatal(err)
	}
	if err := FailIncompleteTasks(db, "agent restarted"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pending", "scanning"} {
		task, err := GetTask(db, id)
		if err != nil || task == nil {
			t.Fatalf("get %q: task=%#v err=%v", id, task, err)
		}
		if task.Phase != "FAILED" || task.EndedAt == 0 || task.Error != "agent restarted" {
			t.Fatalf("interrupted task %q = %#v", id, task)
		}
	}
	completed, err := GetTask(db, "complete")
	if err != nil || completed.Phase != "COMPLETED" {
		t.Fatalf("completed task changed: task=%#v err=%v", completed, err)
	}
}
