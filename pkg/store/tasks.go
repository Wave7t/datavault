package store

import (
	"database/sql"
	"fmt"
	"time"
)

// TaskRecord represents a single backup/restore task in the history log.
type TaskRecord struct {
	TaskID    string
	ServerID  string
	Username  string
	Phase     string
	StatsJSON string
	Error     string
	StartedAt int64
	EndedAt   int64
}

// MigrateTasks creates the task_history table if it does not exist.
func MigrateTasks(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS task_history (
			task_id    TEXT PRIMARY KEY,
			server_id  TEXT NOT NULL,
			username   TEXT NOT NULL,
			phase      TEXT NOT NULL DEFAULT 'PENDING',
			stats_json TEXT,
			error      TEXT,
			started_at INTEGER NOT NULL,
			ended_at   INTEGER
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate task_history: %w", err)
	}
	return nil
}

// InsertTask creates a new task record with phase PENDING and StartedAt set to now.
func InsertTask(db *sql.DB, t TaskRecord) error {
	t.StartedAt = time.Now().Unix()
	_, err := db.Exec(`
		INSERT INTO task_history (task_id, server_id, username, phase, started_at)
		VALUES (?, ?, ?, 'PENDING', ?)
	`, t.TaskID, t.ServerID, t.Username, t.StartedAt)
	if err != nil {
		return fmt.Errorf("insert task: %w", err)
	}
	return nil
}

// UpdateTaskPhase updates the phase and optional stats for a task.
// When phase is COMPLETED or FAILED, ended_at is automatically set to now.
func UpdateTaskPhase(db *sql.DB, taskID, phase, statsJSON string) error {
	now := time.Now().Unix()
	var ended *int64
	if phase == "COMPLETED" || phase == "FAILED" {
		ended = &now
	}
	_, err := db.Exec(`
		UPDATE task_history
		SET phase = ?, stats_json = ?, ended_at = ?
		WHERE task_id = ?
	`, phase, statsJSON, ended, taskID)
	if err != nil {
		return fmt.Errorf("update task phase: %w", err)
	}
	return nil
}

// UpdateTaskFailure records a terminal failure with a diagnostic suitable for
// the local status API and an operator's incident investigation.
func UpdateTaskFailure(db *sql.DB, taskID, reason string) error {
	if reason == "" {
		reason = "task failed"
	}
	_, err := db.Exec(`
		UPDATE task_history
		SET phase = 'FAILED', error = ?, ended_at = ?
		WHERE task_id = ?
	`, reason, time.Now().Unix(), taskID)
	if err != nil {
		return fmt.Errorf("update task failure: %w", err)
	}
	return nil
}

// FailIncompleteTasks marks work that was in progress when the Agent stopped
// as failed. A sync cannot be safely resumed from its in-memory tracker after
// restart, so leaving these rows in PENDING/SCANNING/TRANSFERRING would make
// status clients wait forever and misrepresent the backup as active.
func FailIncompleteTasks(db *sql.DB, reason string) error {
	if reason == "" {
		reason = "agent stopped before task completed"
	}
	_, err := db.Exec(`
		UPDATE task_history
		SET phase = 'FAILED', error = ?, ended_at = ?
		WHERE phase NOT IN ('COMPLETED', 'FAILED')
	`, reason, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("fail incomplete tasks: %w", err)
	}
	return nil
}

// GetTask retrieves a task record by its ID.
// Returns nil, nil if no matching task exists.
func GetTask(db *sql.DB, taskID string) (*TaskRecord, error) {
	row := db.QueryRow(`
		SELECT task_id, server_id, username, phase, COALESCE(stats_json,''),
		       COALESCE(error,''), started_at, COALESCE(ended_at,0)
		FROM task_history WHERE task_id = ?
	`, taskID)
	return scanTask(row)
}

// GetLatestTaskForUser retrieves the most recently started task for a user.
// It lets the local CLI resolve an omitted task ID after an Agent restart,
// when no in-memory progress tracker remains.
func GetLatestTaskForUser(db *sql.DB, username string) (*TaskRecord, error) {
	row := db.QueryRow(`
		SELECT task_id, server_id, username, phase, COALESCE(stats_json,''),
		       COALESCE(error,''), started_at, COALESCE(ended_at,0)
		FROM task_history WHERE username = ?
		ORDER BY started_at DESC, task_id DESC LIMIT 1
	`, username)
	return scanTask(row)
}

func scanTask(row *sql.Row) (*TaskRecord, error) {
	var t TaskRecord
	err := row.Scan(&t.TaskID, &t.ServerID, &t.Username, &t.Phase,
		&t.StatsJSON, &t.Error, &t.StartedAt, &t.EndedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get task: %w", err)
	}
	return &t, nil
}
