// Command datavault-agent is the agent daemon for the datavault backup system.
// It runs on each client machine, schedules backup syncs, and exposes a gRPC
// service on a Unix socket for the dvault CLI to manage user backup rules and
// trigger on-demand sync operations.
//
// Signal handling:
//
//	SIGHUP            reload config from disk
//	SIGTERM / SIGINT  graceful shutdown (waits for in-flight RPCs)
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/example/datavault/internal/agent/orchestrator"
	"github.com/example/datavault/internal/agent/pool"
	"github.com/example/datavault/internal/agent/scheduler"
	"github.com/example/datavault/internal/agent/svc"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
	"google.golang.org/grpc"
)

func main() {
	configPath := flag.String("config", "/etc/datavault/agent/config.yaml", "config file path")
	socketPath := flag.String("socket", "/var/run/datavault-agent.sock", "gRPC Unix socket path")
	dbPath := flag.String("db", "/var/lib/datavault/agent/state.db", "SQLite database path")
	rulesDir := flag.String("rules-dir", "/etc/datavault/agent/user-rules", "user rules YAML directory")
	flag.Parse()

	cfg, err := config.LoadAgentConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Open SQLite with WAL mode.
	db, err := store.OpenDB(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := store.MigrateSnapshots(db); err != nil {
		log.Fatalf("migrate snapshots: %v", err)
	}
	if err := store.MigrateTasks(db); err != nil {
		log.Fatalf("migrate tasks: %v", err)
	}

	// User rule store (per-user YAML files).
	userRuleStore := rules.NewUserRuleStore(*rulesDir)

	// Connection pool to backup server(s) via mTLS gRPC.
	connPool, err := pool.New(cfg.Agent.CertFile, cfg.Agent.KeyFile)
	if err != nil {
		log.Fatalf("init connection pool: %v", err)
	}
	defer connPool.Close()

	// Orchestrator coordinates scan -> diff -> push pipeline.
	orch := orchestrator.New(cfg, connPool, db, userRuleStore)

	// Cron scheduler for machine-level backup rules.
	sched := scheduler.New()
	for _, rule := range cfg.MachineRules {
		if !rule.Enabled {
			continue
		}
		ruleName := rule.Name // capture for closure
		if err := sched.AddJob(scheduler.Job{
			Name:     "machine-" + ruleName,
			Schedule: rule.Schedule,
			Fn: func() {
				if _, err := orch.RunSync("_machine", ruleName); err != nil {
					log.Printf("machine sync %q: %v", ruleName, err)
				}
			},
		}); err != nil {
			log.Printf("schedule machine rule %q: %v", ruleName, err)
		}
	}
	sched.Start()
	defer sched.Stop()

	// Build the gRPC service implementation, wiring orchestrator hooks.
	agentSvc := &svc.AgentService{
		Cfg:           cfg,
		DB:            db,
		UserRuleStore: userRuleStore,
		ConfigPath:    *configPath,
		TriggerSyncFn: func(username, ruleName string) (string, error) {
			return orch.RunSync(username, ruleName)
		},
		GetStatusFn: func(taskID string) (*agentpbv1.SyncStatusUpdate, error) {
			tracker, err := orch.GetTracker(taskID)
			if err != nil {
				return nil, err
			}
			phase, stats, files := tracker.Snapshot()
			return &agentpbv1.SyncStatusUpdate{
				TaskId:       taskID,
				Phase:        string(phase),
				CurrentFiles: files,
				Stats: &agentpbv1.SyncStats{
					TotalFiles:       stats.TotalFiles,
					ScannedFiles:     stats.ScannedFiles,
					ChangedFiles:     stats.ChangedFiles,
					TransferredFiles: stats.TransferredFiles,
					TransferredBytes: stats.TransferredBytes,
					CurrentRateBps:   stats.CurrentRateBPS,
				},
			}, nil
		},
		RequestRestoreFn: func(username string, uid uint32, targetPath string, nonce, signature []byte) (string, error) {
			return orch.RunRestore(username, uid, targetPath, nonce, signature)
		},
		GetQuotaUsageFn: func(username string, nonce, signature []byte) (*agentpbv1.QuotaUsage, error) {
			usage, err := orch.GetQuotaUsage(username, nonce, signature)
			if err != nil {
				return nil, err
			}
			return &agentpbv1.QuotaUsage{
				UsedBytes:  usage.UsedBytes,
				QuotaBytes: usage.QuotaBytes,
				Dataset:    usage.Dataset,
				Server:     cfg.Servers[0].Address,
			}, nil
		},
		GetAuthChallengeFn: func() (*agentpbv1.AuthChallenge, error) {
			server, challenge, err := orch.GetAuthChallenge()
			if err != nil {
				return nil, err
			}
			return &agentpbv1.AuthChallenge{
				Nonce:     challenge.Nonce,
				ExpiresAt: challenge.ExpiresAt,
				Server:    server,
			}, nil
		},
	}

	// Remove stale socket file and create the listening socket.
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("remove stale socket: %v", err)
	}

	// Ensure parent directory exists.
	socketDir := filepath.Dir(*socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		log.Fatalf("create socket directory: %v", err)
	}

	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen on %s: %v", *socketPath, err)
	}
	if err := os.Chmod(*socketPath, 0666); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}
	lis = auth.NewPeerCredListener(lis)

	srv := grpc.NewServer()
	agentpbv1.RegisterAgentServiceServer(srv, agentSvc)

	// Signal handling: SIGHUP reloads config, SIGTERM/SIGINT graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				log.Println("received SIGHUP, reloading config...")
				newCfg, err := config.LoadAgentConfig(*configPath)
				if err != nil {
					log.Printf("reload config: %v", err)
					continue
				}
				// Update config in-place so orch and agentSvc see the new values.
				*cfg = *newCfg
				agentSvc.Cfg = cfg
				log.Println("config reloaded successfully")
			case syscall.SIGTERM, syscall.SIGINT:
				log.Printf("received %v, shutting down gracefully...", sig)
				srv.GracefulStop()
				return
			}
		}
	}()

	log.Printf("datavault-agent listening on %s", *socketPath)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
