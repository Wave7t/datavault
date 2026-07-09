// Package svc implements the AgentService gRPC server for the datavault agent.
// The agent runs on each client machine and exposes a Unix socket gRPC endpoint
// for the `dvault` CLI to manage user backup rules and trigger sync operations.
package svc

import (
	"database/sql"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
)

// AgentService is the concrete implementation of the AgentService gRPC server.
// It embeds the generated UnimplementedAgentServiceServer for forward compatibility
// with new RPCs added to the proto definition.
//
// Function hooks (TriggerSyncFn, GetStatusFn, RequestRestoreFn) are used to
// break the circular dependency between the service layer and the orchestrator.
// They are wired up during agent startup in cmd/datavault-agent/main.go.
type AgentService struct {
	agentpbv1.UnimplementedAgentServiceServer

	Cfg           *config.AgentConfig
	DB            *sql.DB
	UserRuleStore *rules.UserRuleStore

	// TriggerSyncFn is called to start a sync for a given user and rule.
	// An empty ruleName means "all rules". Returns a task ID.
	TriggerSyncFn func(username, ruleName string) (string, error)

	// GetStatusFn returns the current sync status for a task.
	// An empty taskID means "latest task".
	GetStatusFn func(taskID string) (*agentpbv1.SyncStatusUpdate, error)

	// RequestRestoreFn initiates a restore for the given user to targetPath.
	// An empty targetPath means ~/restored/. Returns a task ID.
	RequestRestoreFn func(username, targetPath string) (string, error)
}
