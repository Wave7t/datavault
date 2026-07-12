// datavault-server is the server daemon entry point for the datavault backup system.
// It listens for gRPC connections from datavault agents over mTLS and manages
// per-user ZFS datasets for backup storage with snapshot lifecycle management.
//
// Signal handling:
//   - SIGHUP: reload server configuration from disk
//   - SIGTERM/SIGINT: graceful shutdown of the gRPC server
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/internal/server/receiver"
	"github.com/example/datavault/internal/server/svc"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/tlsconfig"
	"github.com/example/datavault/pkg/zfs"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

func main() {
	configPath := flag.String("config", "/etc/datavault/server/config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Open SQLite for nonce storage
	db, err := store.OpenDB("/var/lib/datavault/server/state.db")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := store.MigrateNonces(db); err != nil {
		log.Fatalf("migrate nonces: %v", err)
	}

	// ZFS manager for dataset and snapshot operations
	zfsMgr, err := zfs.New(cfg.Server.BackupPool)
	if err != nil {
		log.Fatalf("init ZFS: %v", err)
	}

	// Data receiver for writing backup files to ZFS mount points
	recv := receiver.New("/" + cfg.Server.BackupPool)

	// TLS configuration with mutual TLS (mTLS)
	cert, err := tls.LoadX509KeyPair(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		log.Fatalf("load TLS cert: %v", err)
	}

	clientCAs, err := tlsconfig.LoadCertPool(cfg.Server.CAFile)
	if err != nil {
		log.Fatalf("load client CA: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    clientCAs,
	}

	// Auth interceptor for mTLS CN verification, nonce validation, and SSH signature checks
	authStreamInterceptor := middleware.AuthStreamInterceptor(cfg, db)
	authUnaryInterceptor := middleware.AuthInterceptor(cfg, db)

	// gRPC server with mTLS, keepalive enforcement, and auth interceptors
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: false,
		}),
		grpc.MaxConcurrentStreams(100),
		grpc.MaxRecvMsgSize(16*1024*1024),
		grpc.MaxSendMsgSize(16*1024*1024),
		grpc.StreamInterceptor(authStreamInterceptor),
		grpc.UnaryInterceptor(authUnaryInterceptor),
	)

	// Register BackupService implementation
	backupSvc := &svc.BackupServer{
		Cfg:      cfg,
		DB:       db,
		ZFS:      zfsMgr,
		KeysDir:  "/etc/datavault/server/authorized_keys",
		Receiver: recv,
	}
	backuppbv1.RegisterBackupServiceServer(srv, backupSvc)

	// Signal handling for config reload and graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				newCfg, err := config.LoadServerConfig(*configPath)
				if err != nil {
					log.Printf("reload config: %v", err)
				} else {
					*cfg = *newCfg
					backupSvc.Cfg = cfg
					log.Println("config reloaded")
				}
			case syscall.SIGTERM, syscall.SIGINT:
				log.Println("shutting down...")
				srv.GracefulStop()
				return
			}
		}
	}()

	lis, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	fmt.Fprintf(os.Stderr, "datavault-server listening on %s\n", cfg.Server.Listen)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
