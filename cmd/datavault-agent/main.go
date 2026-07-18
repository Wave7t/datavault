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
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/example/datavault/internal/agent/orchestrator"
	"github.com/example/datavault/internal/agent/pool"
	"github.com/example/datavault/internal/agent/scheduler"
	"github.com/example/datavault/internal/agent/svc"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/hooks"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
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
	if err := store.FailIncompleteTasks(db, "agent restarted before task completed"); err != nil {
		log.Fatalf("finalize interrupted tasks: %v", err)
	}

	// User rule store (per-user YAML files).
	userRuleStore := rules.NewUserRuleStore(*rulesDir)

	// Connection pool to backup server(s) via mTLS gRPC.
	connPool, err := pool.New(cfg.Agent.CertFile, cfg.Agent.KeyFile, cfg.Agent.CAFile)
	if err != nil {
		log.Fatalf("init connection pool: %v", err)
	}
	defer connPool.Close()

	// Orchestrator coordinates scan -> diff -> push pipeline.
	orch := orchestrator.New(cfg, connPool, db, userRuleStore)
	orch.SetFailureHook(func(event hooks.TaskFailure) {
		if err := hooks.RunTaskFailed(context.Background(), cfg.Hooks.OnTaskFailed, event); err != nil {
			log.Printf("run task failure hook: %v", err)
		}
	})

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
				if window := cfg.ScheduleWindow; window != nil {
					allowed, err := scheduler.WithinWindow(time.Now(), window.Start, window.End)
					if err != nil {
						log.Printf("evaluate schedule window for machine rule %q: %v", ruleName, err)
						return
					}
					if !allowed {
						log.Printf("skip machine sync %q outside configured schedule window", ruleName)
						return
					}
				}
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
		TriggerSyncFn: func(username, ruleName, sshAuthSock string, uid uint32) (string, error) {
			return orch.RunSyncWithSigner(username, ruleName, func(payload []byte) ([]byte, *ssh.Signature, error) {
				return auth.SignWithSSHAgentForUser(sshAuthSock, uid, payload)
			})
		},
		GetStatusFn: func(username, taskID string) (*agentpbv1.SyncStatusUpdate, error) {
			tracker, err := orch.GetTrackerForUser(username, taskID)
			if err != nil {
				return nil, err
			}
			phase, stats, files := tracker.Snapshot()
			failureReason := ""
			if task, taskErr := store.GetTask(db, taskID); taskErr == nil && task != nil {
				failureReason = task.Error
			}
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
				Error: failureReason,
			}, nil
		},
		RequestRestoreFn: func(username string, uid uint32, targetPath, server string, nonce, signature []byte) (string, error) {
			return orch.RunRestore(username, uid, targetPath, server, nonce, signature)
		},
		GetQuotaUsageFn: func(username, server string, nonce, signature []byte) (*agentpbv1.QuotaUsage, error) {
			usage, err := orch.GetQuotaUsage(username, server, nonce, signature)
			if err != nil {
				return nil, err
			}
			result := &agentpbv1.QuotaUsage{
				UsedBytes:  usage.UsedBytes,
				QuotaBytes: usage.QuotaBytes,
				Dataset:    usage.Dataset,
				Server:     server,
			}
			if cfg.Hooks.OnQuotaWarning != "" && cfg.QuotaWarningPercent > 0 && quotaWarningReached(result.UsedBytes, result.QuotaBytes, cfg.QuotaWarningPercent) {
				go func() {
					if err := hooks.RunQuotaWarning(context.Background(), cfg.Hooks.OnQuotaWarning, hooks.QuotaWarning{Username: username, Server: result.Server, Used: result.UsedBytes, Quota: result.QuotaBytes}); err != nil {
						log.Printf("run quota warning hook: %v", err)
					}
				}()
			}
			return result, nil
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

func quotaWarningReached(used, quota, percent int64) bool {
	if used < 0 || quota <= 0 || percent <= 0 {
		return false
	}
	whole := quota / 100
	remainder := quota % 100
	threshold := whole*percent + (remainder*percent+99)/100
	return used >= threshold
}
