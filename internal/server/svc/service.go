// Package svc implements the gRPC BackupService handlers for the datavault server.
package svc

import (
	"database/sql"

	"github.com/example/datavault/internal/server/receiver"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/zfs"
)

// BackupServer implements the BackupService gRPC server.
// It embeds the UnimplementedBackupServiceServer for forward compatibility
// with new methods added to the proto definition.
type BackupServer struct {
	backuppbv1.UnimplementedBackupServiceServer

	Cfg      *config.ServerConfig
	DB       *sql.DB
	ZFS      *zfs.ZFS
	KeysDir  string             // directory containing authorized_keys
	Receiver *receiver.Receiver // data receiving engine for PushBackup
}
