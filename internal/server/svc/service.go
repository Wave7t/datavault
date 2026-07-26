// Package svc implements the gRPC BackupService handlers for the datavault server.
package svc

import (
	"database/sql"
	"log"
	"time"

	"github.com/example/datavault/internal/server/receiver"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
)

const maxStreamDuration = 10 * time.Minute

// ZFSPool is the subset of *zfs.ZFS operations used by the backup handlers.
// Declared as an interface so tests can substitute a fake without exec'ing zfs.
type ZFSPool interface {
	CreateDataset(name string) error
	EnsureDatasetMounted(name string) error
	SetQuota(dataset string, quotaGB int64) error
	GetUsed(dataset string) (int64, error)
	CreateSnapshot(dataset string) (string, error)
	CleanupSnapshots(dataset string, minKeep, maxKeep int, minFreeGB int64) error
	LatestSnapshot(dataset string) (string, error)
	CreateRestoreClone(snapshot string) (clone, mountpoint string, err error)
	DestroyRestoreClone(clone string) error
}

// BackupServer implements the BackupService gRPC server.
// It embeds the UnimplementedBackupServiceServer for forward compatibility
// with new methods added to the proto definition.
type BackupServer struct {
	backuppbv1.UnimplementedBackupServiceServer

	Cfg      *config.ServerConfig
	DB       *sql.DB
	ZFS      ZFSPool
	KeysDir  string             // directory containing authorized_keys
	Receiver *receiver.Receiver // data receiving engine for PushBackup
	Logger   *log.Logger        // destination for auth audit log lines
}
