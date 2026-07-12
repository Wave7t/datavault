package svc

import (
	"testing"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateBackupIdentity(t *testing.T) {
	tests := []struct {
		name  string
		batch *backuppbv1.BackupBatch
		code  codes.Code
	}{
		{name: "user", batch: &backuppbv1.BackupBatch{Username: "alice", RuleType: "user"}, code: codes.OK},
		{name: "machine", batch: &backuppbv1.BackupBatch{Username: "_machine", RuleType: "machine"}, code: codes.OK},
		{name: "unknown rule", batch: &backuppbv1.BackupBatch{Username: "alice", RuleType: "admin"}, code: codes.InvalidArgument},
		{name: "user machine dataset", batch: &backuppbv1.BackupBatch{Username: "_machine", RuleType: "user"}, code: codes.PermissionDenied},
		{name: "machine user dataset", batch: &backuppbv1.BackupBatch{Username: "alice", RuleType: "machine"}, code: codes.PermissionDenied},
		{name: "machine credentials", batch: &backuppbv1.BackupBatch{Username: "_machine", RuleType: "machine", Nonce: []byte("nonce")}, code: codes.InvalidArgument},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateBackupIdentity(test.batch)
			if got := status.Code(err); got != test.code {
				t.Fatalf("status code = %v, want %v (err=%v)", got, test.code, err)
			}
		})
	}
}
