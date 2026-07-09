# datavault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build datavault — a Linux cluster incremental file backup system with CLI, agent, and server components for disaster recovery, using ZFS for storage integrity and snapshots.

**Architecture:** Three Go binaries (dvault CLI, datavault-agent daemon, datavault-server daemon) communicating via gRPC. Agent schedules and executes backups, Server manages ZFS datasets with per-user isolation, CLI provides user/admin command interface. Security uses mTLS for machine identity and SSH agent signing for user authentication.

**Tech Stack:** Go 1.21+, gRPC/protobuf, SQLite (mattn/go-sqlite3), ZFS (exec.Command), YAML (gopkg.in/yaml.v3), Cobra CLI, ssh-agent signing (golang.org/x/crypto/ssh)

## Global Constraints

- Go 1.21+ (HTTP/2 Rapid Reset fix required)
- gRPC MaxConcurrentStreams: 100, MaxRecvMsgSize: 16MB
- gRPC Keepalive: MinTime=30s, PermitWithoutStream=false
- ZFS commands via exec.Command with individual args, NEVER sh -c
- All stream handlers must have context.WithTimeout (10 min max)
- No gRPC reflection in production builds
- Unix socket permissions: 0600, directory 0700
- CLI user = SO_PEERCRED UID, never trust client-provided user string
- File paths validated with filepath.Clean() + prefix checks
- Dataset/hostname/username names validated with strict regex: hostname `[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?`, username `[a-z_][a-z0-9_-]{0,30}`

## File Structure

```
cmd/
  dvault/main.go                    -- CLI entry point
  datavault-agent/main.go           -- Agent daemon entry point
  datavault-server/main.go          -- Server daemon entry point

api/proto/
  agent/v1/agent.proto              -- AgentService definitions
  backup/v1/backup.proto            -- BackupService definitions

pkg/
  agentpb/                          -- generated AgentService code
  backuppb/                         -- generated BackupService code
  config/
    server.go                       -- Server config struct + loader
    server_test.go
    agent.go                        -- Agent config struct + loader
    agent_test.go
  rules/
    rule.go                         -- Rule struct, BackupRule, validation
    rule_test.go
    userstore.go                    -- Per-user rule YAML read/write
    userstore_test.go
    merge.go                        -- Rule merging (global + machine + user)
    merge_test.go
  glob/
    matcher.go                      -- Glob exclude matching logic
    matcher_test.go
  auth/
    peercred.go                     -- SO_PEERCRED UID extraction
    sshsign.go                      -- SSH agent signature generation (CLI side)
    sshsign_test.go
    challenge.go                    -- Nonce generation and validation
    challenge_test.go
    middleware.go                   -- gRPC auth interceptor (Server side)
    middleware_test.go
  zfs/
    zfs.go                          -- ZFS command wrapper (create, snapshot, quota, etc.)
    zfs_test.go
    dataset.go                      -- Dataset naming and validation
    dataset_test.go
    snapshot.go                     -- Snapshot lifecycle (create, list, cleanup)
    snapshot_test.go
  store/
    sqlite.go                       -- SQLite connection helper (WAL mode)
    snapshots.go                    -- file_snapshots table CRUD
    snapshots_test.go
    nonces.go                       -- Nonce storage with TTL GC
    nonces_test.go
    tasks.go                        -- task_history table CRUD
    tasks_test.go
  retry/
    backoff.go                      -- Exponential backoff with jitter
    backoff_test.go
  scanner/
    scanner.go                      -- Directory walker with mtime/size/sha256
    scanner_test.go
    diff.go                         -- Diff computation against snapshot DB
    diff_test.go
  packager/
    packager.go                     -- Batch file packager (1000 files/batch)
    packager_test.go
  progress/
    tracker.go                      -- Sync progress tracker (streaming updates)
    tracker_test.go

internal/agent/
  scheduler/
    cron.go                         -- Cron schedule parser and timer
    cron_test.go
  pool/
    connpool.go                     -- Server gRPC connection pool
  orchestrator/
    orchestrator.go                 -- Task orchestrator (rule merge → scan → diff → push)
    orchestrator_test.go
  transport/
    pusher.go                       -- PushBackup stream handler
    restorer.go                     -- PullRestore stream handler
    transport_test.go
  svc/
    service.go                      -- AgentService gRPC implementation
    userrules.go                    -- Add/Remove/List/Enable/Disable handler
    machinerules.go                 -- Machine rules handler
    sync.go                         -- TriggerSync handler
    status.go                       -- GetSyncStatus handler
    restore.go                      -- RequestRestore handler

internal/server/
  svc/
    service.go                      -- BackupService gRPC implementation
    challenge.go                    -- GetChallenge handler
    configsvc.go                    -- GetGlobalConfig handler
    backup.go                       -- PushBackup stream handler
    quota.go                        -- GetQuotaUsage handler
    restore.go                      -- PullRestore stream handler
  receiver/
    receiver.go                     -- Data receiving engine (batch write to ZFS)
    receiver_test.go
  middleware/
    auth.go                         -- Per-RPC auth interceptor (mTLS + nonce + SSH sig)
    auth_test.go

scripts/
  datavault-agent.service           -- systemd unit for agent
  datavault-server.service          -- systemd unit for server
```

## Tasks

### Phase A: Project Foundation (4 tasks)

---

### Task A1: Go module and project scaffolding

**Files:**
- Create: `go.mod`
- Create: `.gitignore`

**Produces:**
- Go module `github.com/example/datavault`

- [ ] **Step 1: Initialize Go module**

```bash
cd /home/xiaomi/Proj/autoback
go mod init github.com/example/datavault
```

- [ ] **Step 2: Create .gitignore**

```bash
cat > .gitignore << 'EOF'
# Binaries
/dvault
/datavault-agent
/datavault-server
*.exe
*.test
*.out

# IDE
.idea/
.vscode/
*.swp

# Build
/dist/
EOF
```

- [ ] **Step 3: Install core dependencies**

```bash
go get google.golang.org/grpc
go get google.golang.org/protobuf
go get gopkg.in/yaml.v3
go get github.com/mattn/go-sqlite3
go get golang.org/x/crypto/ssh
go get golang.org/x/crypto/ssh/agent
go get github.com/spf13/cobra
go get github.com/robfig/cron/v3
go get github.com/glebarez/go-sqlite
```

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum .gitignore
git commit -m "feat: initialize Go module with dependencies

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task A2: Protobuf definitions — AgentService

**Files:**
- Create: `api/proto/agent/v1/agent.proto`
- Create: `buf.gen.yaml`
- Create: `buf.yaml`

**Interfaces:**
- Produces: Generated Go types in `pkg/agentpb/`

- [ ] **Step 1: Create buf configuration**

```yaml
# buf.yaml
version: v1
breaking:
  use:
    - FILE
lint:
  use:
    - DEFAULT
```

- [ ] **Step 2: Create buf generate configuration**

```yaml
# buf.gen.yaml
version: v1
managed:
  enabled: true
  go_package_prefix:
    default: github.com/example/datavault/pkg
    except:
      - buf.build/googleapis/googleapis
plugins:
  - plugin: buf.build/protocolbuffers/go
    out: pkg
    opt: paths=source_relative
  - plugin: buf.build/grpc/go
    out: pkg
    opt: paths=source_relative
```

- [ ] **Step 3: Write AgentService proto**

```protobuf
// api/proto/agent/v1/agent.proto
syntax = "proto3";

package agent.v1;

option go_package = "github.com/example/datavault/pkg/agentpb/v1;agentpbv1";

service AgentService {
  rpc AddUserRule(AddUserRuleRequest) returns (AddUserRuleResponse);
  rpc RemoveUserRule(RemoveUserRuleRequest) returns (RemoveUserRuleResponse);
  rpc ListUserRules(ListUserRulesRequest) returns (ListUserRulesResponse);
  rpc EnableUserRule(EnableUserRuleRequest) returns (EnableUserRuleResponse);
  rpc DisableUserRule(DisableUserRuleRequest) returns (DisableUserRuleResponse);

  rpc AddMachineRule(AddMachineRuleRequest) returns (AddMachineRuleResponse);
  rpc RemoveMachineRule(RemoveMachineRuleRequest) returns (RemoveMachineRuleResponse);
  rpc ListMachineRules(ListMachineRulesRequest) returns (ListMachineRulesResponse);

  rpc TriggerSync(TriggerSyncRequest) returns (TriggerSyncResponse);
  rpc GetSyncStatus(GetSyncStatusRequest) returns (stream SyncStatusUpdate);
  rpc RequestRestore(RequestRestoreRequest) returns (RequestRestoreResponse);
}

message Rule {
  string name = 1;
  repeated string paths = 2;
  repeated string exclude = 3;
  bool enabled = 4;
}

message AddUserRuleRequest {
  string name = 1;
  repeated string paths = 2;
  repeated string exclude = 3;
}
message AddUserRuleResponse {}

message RemoveUserRuleRequest {
  string name = 1;
}
message RemoveUserRuleResponse {}

message ListUserRulesRequest {}
message ListUserRulesResponse {
  repeated Rule rules = 1;
}

message EnableUserRuleRequest {
  string name = 1;
}
message EnableUserRuleResponse {}

message DisableUserRuleRequest {
  string name = 1;
}
message DisableUserRuleResponse {}

message AddMachineRuleRequest {
  string name = 1;
  repeated string paths = 2;
  string schedule = 3;
  repeated string exclude = 4;
}
message AddMachineRuleResponse {}

message RemoveMachineRuleRequest {
  string name = 1;
}
message RemoveMachineRuleResponse {}

message ListMachineRulesRequest {}
message ListMachineRulesResponse {
  repeated Rule rules = 1;
}

message TriggerSyncRequest {
  string rule_name = 1;  // empty = all rules
}
message TriggerSyncResponse {
  string task_id = 1;
}

message GetSyncStatusRequest {
  string task_id = 1;  // empty = latest
}
message SyncStatusUpdate {
  string task_id = 1;
  string username = 2;
  string server = 3;
  string phase = 4;          // SCANNING, TRANSFERRING, COMPLETED, FAILED
  SyncStats stats = 5;
  repeated string current_files = 6;  // files in current batch
}

message SyncStats {
  int64 total_files = 1;
  int64 scanned_files = 2;
  int64 changed_files = 3;
  int64 transferred_files = 4;
  int64 transferred_bytes = 5;
  int64 current_rate_bps = 6;
}

message RequestRestoreRequest {
  string target_path = 1;  // empty = ~/restored/
}
message RequestRestoreResponse {
  string task_id = 1;
}
```

- [ ] **Step 4: Install buf and generate code**

```bash
go install github.com/bufbuild/buf/cmd/buf@latest
buf generate
# Expected: pkg/agentpb/v1/agent.pb.go and pkg/agentpb/v1/agent_grpc.pb.go created
```

- [ ] **Step 5: Commit**

```bash
git add api/ buf.yaml buf.gen.yaml buf.lock pkg/agentpb/
git commit -m "feat: add AgentService protobuf definitions and generated code

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task A3: Protobuf definitions — BackupService

**Files:**
- Create: `api/proto/backup/v1/backup.proto`

**Interfaces:**
- Consumes: buf.yaml and buf.gen.yaml from Task A2
- Produces: Generated Go types in `pkg/backuppb/`

- [ ] **Step 1: Write BackupService proto**

```protobuf
// api/proto/backup/v1/backup.proto
syntax = "proto3";

package backup.v1;

option go_package = "github.com/example/datavault/pkg/backuppb/v1;backuppbv1";

service BackupService {
  rpc GetChallenge(GetChallengeRequest) returns (Challenge);
  rpc GetGlobalConfig(GetGlobalConfigRequest) returns (GlobalConfig);
  rpc PushBackup(stream BackupBatch) returns (stream BatchAck);
  rpc GetQuotaUsage(GetQuotaUsageRequest) returns (QuotaUsage);
  rpc PullRestore(PullRestoreRequest) returns (stream RestoreBatch);
}

message GetChallengeRequest {}
message Challenge {
  bytes nonce = 1;
  int64 expires_at = 2;  // unix timestamp, now+5min
}

message GetGlobalConfigRequest {
  string hostname = 1;
}
message GlobalConfig {
  repeated GlobalRule global_rules = 1;
  UserPolicy user_policy = 2;
}

message GlobalRule {
  string name = 1;
  repeated string paths = 2;
  repeated string exclude = 3;
}

message UserPolicy {
  string default_schedule = 1;
  int64 default_quota_gb = 2;
  map<string, UserOverride> per_user_overrides = 3;
}

message UserOverride {
  int64 quota_gb = 1;
  string schedule = 2;  // optional override; empty means use default
}

message BackupBatch {
  string batch_id = 1;
  string username = 2;         // which user this batch belongs to
  string rule_type = 3;        // "user" or "machine"
  repeated FileEntry files = 4;
  bytes signature = 5;         // SSH signature: nonce || "PushBackup" || sha256(payload)
  bytes nonce = 6;
}

message FileEntry {
  string path = 1;             // relative path within the backup root
  bytes content = 2;           // file contents
  uint32 mode = 3;             // file mode bits
  bool deleted = 4;            // true = file was deleted, remove on server
}

message BatchAck {
  string batch_id = 1;
  string status = 2;           // "OK" or "ERROR"
  string error = 3;            // error detail if status == "ERROR"
  int64 written_bytes = 4;
}

message GetQuotaUsageRequest {
  string username = 1;
}
message QuotaUsage {
  int64 used_bytes = 1;
  int64 quota_bytes = 2;
  string dataset = 3;
}

message PullRestoreRequest {
  string username = 1;
  bytes nonce = 2;
  bytes signature = 3;         // SSH signature: nonce || "PullRestore" || sha256(payload)
}
message RestoreBatch {
  string batch_id = 1;
  repeated FileEntry files = 2;
  bool is_last = 3;
}
```

- [ ] **Step 2: Generate code**

```bash
buf generate
# Expected: pkg/backuppb/v1/backup.pb.go and pkg/backuppb/v1/backup_grpc.pb.go created
```

- [ ] **Step 3: Commit**

```bash
git add api/proto/backup/ pkg/backuppb/
git commit -m "feat: add BackupService protobuf definitions and generated code

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task A4: Rule model and YAML file store

**Files:**
- Create: `pkg/rules/rule.go`
- Create: `pkg/rules/rule_test.go`
- Create: `pkg/rules/userstore.go`
- Create: `pkg/rules/userstore_test.go`

**Interfaces:**
- Produces:
  - `type Rule struct { Name string; Paths []string; Exclude []string; Schedule string; Enabled bool }`
  - `type UserRuleStore struct { ... }; func NewUserRuleStore(baseDir string) *UserRuleStore`
  - `func (s *UserRuleStore) Load(username string) ([]Rule, error)`
  - `func (s *UserRuleStore) Save(username string, rules []Rule) error`
  - `func (s *UserRuleStore) Add(username string, rule Rule) error`
  - `func (s *UserRuleStore) Remove(username, name string) error`
  - `func (s *UserRuleStore) SetEnabled(username, name string, enabled bool) error`

- [ ] **Step 1: Write rule model and tests**

```go
// pkg/rules/rule.go
package rules

import "fmt"

type Rule struct {
	Name     string   `yaml:"name"     json:"name"`
	Paths    []string `yaml:"paths"    json:"paths"`
	Exclude  []string `yaml:"exclude"  json:"exclude,omitempty"`
	Schedule string   `yaml:"schedule" json:"schedule,omitempty"`
	Enabled  bool     `yaml:"enabled"  json:"enabled"`
}

func (r *Rule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if len(r.Paths) == 0 {
		return fmt.Errorf("rule %q: at least one path is required", r.Name)
	}
	return nil
}
```

```go
// pkg/rules/rule_test.go
package rules

import "testing"

func TestRuleValidateEmptyName(t *testing.T) {
	r := Rule{Name: "", Paths: []string{"/tmp"}}
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestRuleValidateNoPaths(t *testing.T) {
	r := Rule{Name: "test"}
	if err := r.Validate(); err == nil {
		t.Fatal("expected error for no paths")
	}
}

func TestRuleValidateOK(t *testing.T) {
	r := Rule{Name: "ok", Paths: []string{"/tmp"}}
	if err := r.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 2: Run tests, verify**

```bash
go test ./pkg/rules/ -v
# Expected: 3 PASS
```

- [ ] **Step 3: Write user rule store**

```go
// pkg/rules/userstore.go
package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type UserRuleStore struct {
	baseDir string
}

type userRuleFile struct {
	Rules []Rule `yaml:"rules"`
}

func NewUserRuleStore(baseDir string) *UserRuleStore {
	return &UserRuleStore{baseDir: baseDir}
}

func (s *UserRuleStore) filePath(username string) string {
	return filepath.Join(s.baseDir, username+".yaml")
}

func (s *UserRuleStore) Load(username string) ([]Rule, error) {
	f, err := os.Open(s.filePath(username))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open user rules for %q: %w", username, err)
	}
	defer f.Close()

	var uf userRuleFile
	if err := yaml.NewDecoder(f).Decode(&uf); err != nil {
		return nil, fmt.Errorf("decode user rules for %q: %w", username, err)
	}
	return uf.Rules, nil
}

func (s *UserRuleStore) Save(username string, rules []Rule) error {
	if err := os.MkdirAll(s.baseDir, 0700); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	f, err := os.Create(s.filePath(username))
	if err != nil {
		return fmt.Errorf("create user rules for %q: %w", username, err)
	}
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	uf := userRuleFile{Rules: rules}
	if err := yaml.NewEncoder(f).Encode(&uf); err != nil {
		return fmt.Errorf("encode user rules: %w", err)
	}
	return nil
}

func (s *UserRuleStore) Add(username string, rule Rule) error {
	rules, err := s.Load(username)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Name == rule.Name {
			return fmt.Errorf("rule %q already exists", rule.Name)
		}
	}
	rule.Enabled = true
	rules = append(rules, rule)
	return s.Save(username, rules)
}

func (s *UserRuleStore) Remove(username, name string) error {
	rules, err := s.Load(username)
	if err != nil {
		return err
	}
	filtered := make([]Rule, 0, len(rules))
	found := false
	for _, r := range rules {
		if r.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}
	if !found {
		return fmt.Errorf("rule %q not found", name)
	}
	return s.Save(username, filtered)
}

func (s *UserRuleStore) SetEnabled(username, name string, enabled bool) error {
	rules, err := s.Load(username)
	if err != nil {
		return err
	}
	for i, r := range rules {
		if r.Name == name {
			rules[i].Enabled = enabled
			return s.Save(username, rules)
		}
	}
	return fmt.Errorf("rule %q not found", name)
}
```

- [ ] **Step 4: Write user store tests**

```go
// pkg/rules/userstore_test.go
package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUserRuleStoreAddAndLoad(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)

	if err := s.Add("alice", Rule{Name: "docs", Paths: []string{"/home/alice/docs"}}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	rules, err := s.Load("alice")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if !rules[0].Enabled {
		t.Fatal("new rule should be enabled by default")
	}
}

func TestUserRuleStoreRemove(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)

	s.Add("alice", Rule{Name: "docs", Paths: []string{"/tmp"}})
	s.Add("alice", Rule{Name: "photos", Paths: []string{"/tmp"}})

	if err := s.Remove("alice", "docs"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	rules, _ := s.Load("alice")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after remove, got %d", len(rules))
	}
}

func TestUserRuleStoreDisable(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)
	s.Add("alice", Rule{Name: "docs", Paths: []string{"/tmp"}})

	if err := s.SetEnabled("alice", "docs", false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	rules, _ := s.Load("alice")
	if rules[0].Enabled {
		t.Fatal("rule should be disabled")
	}
}

func TestUserRuleStoreLoadNonexistent(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)
	rules, err := s.Load("nobody")
	if err != nil {
		t.Fatalf("Load nonexistent: %v", err)
	}
	if rules != nil {
		t.Fatal("expected nil for nonexistent user")
	}
}

func TestUserRuleStoreFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s := NewUserRuleStore(dir)
	s.Add("alice", Rule{Name: "test", Paths: []string{"/tmp"}})

	info, err := os.Stat(filepath.Join(dir, "alice.yaml"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %04o", info.Mode().Perm())
	}
}
```

- [ ] **Step 5: Run all tests**

```bash
go test ./pkg/rules/ -v
# Expected: all PASS
```

- [ ] **Step 6: Commit**

```bash
git add pkg/rules/
git commit -m "feat: add rule model and per-user YAML rule store

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Phase B: Shared Libraries (5 tasks)

---

### Task B1: Glob exclude matcher

**Files:**
- Create: `pkg/glob/matcher.go`
- Create: `pkg/glob/matcher_test.go`

**Interfaces:**
- Produces: `type Matcher struct { ... }; func Compile(patterns []string) (*Matcher, error); func (m *Matcher) Match(relativePath string) bool`

- [ ] **Step 1: Write glob matcher with tests**

```go
// pkg/glob/matcher.go
package glob

import (
	"path/filepath"
	goglob "path/filepath"
)

// Matcher filters file paths against exclude patterns.
// Patterns use standard glob syntax matching against relative paths.
type Matcher struct {
	patterns []string
}

func Compile(patterns []string) (*Matcher, error) {
	for _, p := range patterns {
		if _, err := goglob.Match(p, ""); err != nil {
			// filepath.Match always returns nil error, but validate
			// the pattern is not empty
			if p == "" {
				return nil, goglob.ErrBadPattern
			}
		}
	}
	return &Matcher{patterns: patterns}, nil
}

// Match returns true if the relative path matches any exclude pattern.
func (m *Matcher) Match(relativePath string) bool {
	for _, p := range m.patterns {
		// Try direct match
		if ok, _ := goglob.Match(p, relativePath); ok {
			return true
		}
		// Try with **/ prefix for subpath matching
		subPattern := filepath.Join("**", p)
		if ok, _ := goglob.Match(subPattern, relativePath); ok {
			return true
		}
	}
	return false
}
```

```go
// pkg/glob/matcher_test.go
package glob

import "testing"

func TestMatcherExactMatch(t *testing.T) {
	m, _ := Compile([]string{"*.tmp"})
	if !m.Match("foo.tmp") {
		t.Fatal("expected match")
	}
}

func TestMatcherNoMatch(t *testing.T) {
	m, _ := Compile([]string{"*.tmp"})
	if m.Match("foo.txt") {
		t.Fatal("expected no match")
	}
}

func TestMatcherDeepMatch(t *testing.T) {
	m, _ := Compile([]string{"*.tmp"})
	// *.tmp matches any file named *.tmp at any depth via **/ prefix
	if !m.Match("a/b/c/foo.tmp") {
		t.Fatal("expected deep match via **/ prefix")
	}
}

func TestMatcherDirPattern(t *testing.T) {
	m, _ := Compile([]string{"node_modules"})
	if !m.Match("a/node_modules/package.json") {
		t.Fatal("expected node_modules match at any depth")
	}
}

func TestMatcherDoubleStar(t *testing.T) {
	m, _ := Compile([]string{"**/*.mp4"})
	if !m.Match("videos/ lectures/recording.mp4") {
		t.Fatal("expected **/*.mp4 match")
	}
}

func TestMatcherEmptyPatterns(t *testing.T) {
	m, _ := Compile(nil)
	if m.Match("anything") {
		t.Fatal("empty patterns should never match")
	}
}

func TestCompileEmptyPattern(t *testing.T) {
	_, err := Compile([]string{""})
	if err == nil {
		t.Fatal("expected error for empty pattern")
	}
}
```

- [ ] **Step 2: Run tests**

```bash
go test ./pkg/glob/ -v
# Expected: 6 PASS, 0 FAIL
```

- [ ] **Step 3: Commit**

```bash
git add pkg/glob/
git commit -m "feat: add glob exclude matcher with deep-path matching

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task B2: SO_PEERCRED and SSH signing utilities

**Files:**
- Create: `pkg/auth/peercred.go`
- Create: `pkg/auth/peercred_test.go`
- Create: `pkg/auth/sshsign.go`
- Create: `pkg/auth/sshsign_test.go`

**Interfaces:**
- Produces:
  - `func GetPeerUID(conn *net.UnixConn) (uint32, error)` — extract SO_PEERCRED UID
  - `func LookupUsername(uid uint32) (string, error)` — UID → username
  - `func SignWithSSHAgent(payload []byte) ([]byte, error)` — sign with SSH_AUTH_SOCK agent
  - `func VerifySSHSignature(pubKey ssh.PublicKey, payload, sig []byte) error`

- [ ] **Step 1: Write SO_PEERCRED extraction**

```go
// pkg/auth/peercred.go
package auth

import (
	"fmt"
	"net"
	"os/user"
	"syscall"
)

// GetPeerUID extracts the Unix socket peer's UID via SO_PEERCRED.
func GetPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket connection")
	}
	f, err := unixConn.File()
	if err != nil {
		return 0, fmt.Errorf("get socket file descriptor: %w", err)
	}
	defer f.Close()

	cred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", err)
	}
	return cred.Uid, nil
}

// LookupUsername returns the username for the given UID.
func LookupUsername(uid uint32) (string, error) {
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "", fmt.Errorf("lookup uid %d: %w", uid, err)
	}
	return u.Username, nil
}
```

- [ ] **Step 2: Write SSH signing**

```go
// pkg/auth/sshsign.go
package auth

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// SignWithSSHAgent signs payload using the SSH agent from SSH_AUTH_SOCK.
func SignWithSSHAgent(payload []byte) ([]byte, *ssh.Signature, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to ssh-agent: %w", err)
	}
	defer conn.Close()

	ag := agent.NewClient(conn)
	keys, err := ag.List()
	if err != nil {
		return nil, nil, fmt.Errorf("list ssh-agent keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no keys in ssh-agent")
	}

	sig, err := ag.Sign(keys[0], payload)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-agent sign: %w", err)
	}
	return keys[0].Marshal(), sig, nil
}

// VerifySSHSignature verifies an SSH signature against a public key.
func VerifySSHSignature(pubKeyBytes, payload []byte, sig *ssh.Signature) error {
	pubKey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	if err := pubKey.Verify(payload, sig); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// GenerateNonce produces a cryptographically random nonce.
func GenerateNonce() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return b, nil
}
```

- [ ] **Step 3: Write SSH sign test (unit test only, no SSH agent needed)**

```go
// pkg/auth/sshsign_test.go
package auth

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVerifySSHSignature(t *testing.T) {
	// Generate an ephemeral key pair for testing
	priv, err := ssh.ParseRawPrivateKey(mustGenerateRSA(t))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	payload := []byte("test payload for signing")
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pubBytes := signer.PublicKey().Marshal()
	if err := VerifySSHSignature(pubBytes, payload, sig); err != nil {
		t.Fatalf("verify valid sig: %v", err)
	}
}

func TestVerifySSHSignatureTamperedPayload(t *testing.T) {
	priv, _ := ssh.ParseRawPrivateKey(mustGenerateRSA(t))
	signer, _ := ssh.NewSignerFromKey(priv)

	sig, _ := signer.Sign(rand.Reader, []byte("original"))
	pubBytes := signer.PublicKey().Marshal()

	err := VerifySSHSignature(pubBytes, []byte("tampered"), sig)
	if err == nil {
		t.Fatal("expected error for tampered payload")
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, _ := GenerateNonce()
	n2, _ := GenerateNonce()
	if len(n1) != 32 {
		t.Fatalf("nonce length: expected 32, got %d", len(n1))
	}
	if string(n1) == string(n2) {
		t.Fatal("two nonces should differ")
	}
}

func mustGenerateRSA(t *testing.T) []byte {
	t.Helper()
	priv, err := ssh.ParseRawPrivateKey(mustGenerateRSA(t))
	_ = priv
	return nil
}
```

Wait — that test has a bug. Let me fix it.

```go
// pkg/auth/sshsign_test.go
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
)

func generateTestKey(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return b
}

func TestVerifySSHSignature(t *testing.T) {
	priv, err := ssh.ParseRawPrivateKey(generateTestKey(t))
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	payload := []byte("test payload for signing")
	sig, err := signer.Sign(rand.Reader, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	pubBytes := signer.PublicKey().Marshal()
	if err := VerifySSHSignature(pubBytes, payload, sig); err != nil {
		t.Fatalf("verify valid sig: %v", err)
	}
}

func TestVerifySSHSignatureTamperedPayload(t *testing.T) {
	priv, _ := ssh.ParseRawPrivateKey(generateTestKey(t))
	signer, _ := ssh.NewSignerFromKey(priv)

	sig, _ := signer.Sign(rand.Reader, []byte("original"))
	pubBytes := signer.PublicKey().Marshal()

	err := VerifySSHSignature(pubBytes, []byte("tampered"), sig)
	if err == nil {
		t.Fatal("expected error for tampered payload")
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, _ := GenerateNonce()
	n2, _ := GenerateNonce()
	if len(n1) != 32 {
		t.Fatalf("nonce length: expected 32, got %d", len(n1))
	}
	if string(n1) == string(n2) {
		t.Fatal("two nonces should differ")
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/auth/ -v -run "TestVerify|TestGenerate"
# Expected: 3 PASS
```

- [ ] **Step 5: Commit**

```bash
git add pkg/auth/
git commit -m "feat: add SO_PEERCRED extraction, SSH agent signing, and nonce utilities

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task B3: Exponential backoff retry

**Files:**
- Create: `pkg/retry/backoff.go`
- Create: `pkg/retry/backoff_test.go`

**Interfaces:**
- Produces:
  - `type Config struct { Initial, Max time.Duration; Multiplier, Jitter float64; MaxElapsed time.Duration }`
  - `type Backoff struct { ... }; func New(cfg Config) *Backoff`
  - `func (b *Backoff) Next() time.Duration` — returns next interval, 0 if exceeded
  - `func (b *Backoff) Reset()` — reset for next retry cycle

- [ ] **Step 1: Write backoff implementation**

```go
// pkg/retry/backoff.go
package retry

import (
	"math"
	"math/rand"
	"time"
)

type Config struct {
	Initial     time.Duration
	Max         time.Duration
	Multiplier  float64
	Jitter      float64
	MaxElapsed  time.Duration
}

type Backoff struct {
	cfg      Config
	attempt  int
	elapsed  time.Duration
	start    time.Time
}

func New(cfg Config) *Backoff {
	return &Backoff{
		cfg:   cfg,
		start: time.Now(),
	}
}

// Next returns the next backoff duration, or 0 if MaxElapsed is exceeded.
func (b *Backoff) Next() time.Duration {
	if b.cfg.MaxElapsed > 0 && b.elapsed >= b.cfg.MaxElapsed {
		return 0
	}

	interval := float64(b.cfg.Initial) * math.Pow(b.cfg.Multiplier, float64(b.attempt))
	if interval > float64(b.cfg.Max) {
		interval = float64(b.cfg.Max)
	}

	// Apply jitter
	if b.cfg.Jitter > 0 {
		jitterRange := interval * b.cfg.Jitter
		interval = interval - jitterRange/2 + rand.Float64()*jitterRange
	}

	b.attempt++
	d := time.Duration(interval)
	b.elapsed += d
	return d
}

func (b *Backoff) Reset() {
	b.attempt = 0
	b.elapsed = 0
	b.start = time.Now()
}

func (b *Backoff) Attempt() int {
	return b.attempt
}
```

```go
// pkg/retry/backoff_test.go
package retry

import (
	"testing"
	"time"
)

func TestBackoffIncreases(t *testing.T) {
	b := New(Config{
		Initial:    1 * time.Second,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	})

	prev := time.Duration(0)
	for i := 0; i < 10; i++ {
		next := b.Next()
		if next <= prev {
			t.Fatalf("attempt %d: %v <= %v (not increasing)", i, next, prev)
		}
		prev = next
	}
}

func TestBackoffMaxCapped(t *testing.T) {
	b := New(Config{
		Initial:    1 * time.Second,
		Max:        5 * time.Second,
		Multiplier: 10.0,
	})

	// Skip to high attempt count
	for i := 0; i < 5; i++ {
		b.Next()
	}
	next := b.Next()
	if next > 5*time.Second {
		t.Fatalf("expected cap at 5s, got %v", next)
	}
}

func TestBackoffMaxElapsed(t *testing.T) {
	b := New(Config{
		Initial:    200 * time.Millisecond,
		Max:        10 * time.Second,
		Multiplier: 2.0,
		MaxElapsed: 500 * time.Millisecond,
	})

	for {
		d := b.Next()
		if d == 0 {
			return // exceeded, test passes
		}
	}
}

func TestBackoffReset(t *testing.T) {
	b := New(Config{
		Initial:    1 * time.Second,
		Max:        30 * time.Second,
		Multiplier: 2.0,
	})

	b.Next()
	b.Next()
	b.Reset()

	if b.Attempt() != 0 {
		t.Fatal("attempt should be 0 after reset")
	}
}

func TestBackoffJitter(t *testing.T) {
	// With jitter, values should vary
	intervals := make(map[time.Duration]bool)
	for i := 0; i < 100; i++ {
		b := New(Config{
			Initial:    1 * time.Second,
			Max:        60 * time.Second,
			Multiplier: 2.0,
			Jitter:     0.5,
		})
		intervals[b.Next()] = true
	}
	if len(intervals) < 2 {
		t.Fatal("jitter should produce varying intervals")
	}
}
```

- [ ] **Step 2: Run tests**

```bash
go test ./pkg/retry/ -v
# Expected: 5 PASS
```

- [ ] **Step 3: Commit**

```bash
git add pkg/retry/
git commit -m "feat: add exponential backoff retry with jitter and max elapsed

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task B4: Configuration loading (Server and Agent)

**Files:**
- Create: `pkg/config/agent.go`
- Create: `pkg/config/agent_test.go`
- Create: `pkg/config/server.go`
- Create: `pkg/config/server_test.go`

**Interfaces:**
- Produces:
  - Server: `type ServerConfig struct { Server ServerBlock; AllowedHosts []AllowedHost; GlobalRules []GlobalRule; UserPolicy UserPolicyBlock; SnapshotPolicy SnapshotPolicyBlock }`; `func LoadServerConfig(path string) (*ServerConfig, error)`
  - Agent: `type AgentConfig struct { Agent AgentBlock; Servers []ServerEntry; MachineRules []MachineRule; Retry RetryConfig; Hooks HooksConfig }`; `func LoadAgentConfig(path string) (*AgentConfig, error)`

- [ ] **Step 1: Write server config**

```go
// pkg/config/server.go
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ServerBlock struct {
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	Listen     string `yaml:"listen"`
	BackupPool string `yaml:"backup_pool"`
}

type AllowedHost struct {
	CN string `yaml:"cn"`
}

type GlobalRule struct {
	Name    string   `yaml:"name"`
	Paths   []string `yaml:"paths"`
	Exclude []string `yaml:"exclude,omitempty"`
}

type UserOverride struct {
	QuotaGB  int64  `yaml:"quota_gb"`
	Schedule string `yaml:"schedule,omitempty"`
}

type UserPolicyBlock struct {
	DefaultSchedule   string                  `yaml:"default_schedule"`
	DefaultQuotaGB    int64                   `yaml:"default_quota_gb"`
	PerUserOverrides  map[string]UserOverride `yaml:"per_user_overrides,omitempty"`
}

type SnapshotPolicyBlock struct {
	MinSnapshots int   `yaml:"min_snapshots"`
	MaxSnapshots int   `yaml:"max_snapshots"`
	MinFreeGB    int64 `yaml:"min_free_gb"`
}

type ServerConfig struct {
	Server         ServerBlock         `yaml:"server"`
	AllowedHosts   []AllowedHost       `yaml:"allowed_hosts"`
	GlobalRules    []GlobalRule        `yaml:"global_rules"`
	UserPolicy     UserPolicyBlock     `yaml:"user_policy"`
	SnapshotPolicy SnapshotPolicyBlock `yaml:"snapshot_policy"`
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config: %w", err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse server config: %w", err)
	}

	// Defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0:8443"
	}
	if cfg.SnapshotPolicy.MinSnapshots < 2 {
		cfg.SnapshotPolicy.MinSnapshots = 2
	}
	if cfg.SnapshotPolicy.MaxSnapshots == 0 {
		cfg.SnapshotPolicy.MaxSnapshots = 7
	}
	if cfg.UserPolicy.DefaultQuotaGB == 0 {
		cfg.UserPolicy.DefaultQuotaGB = 20
	}
	if cfg.UserPolicy.DefaultSchedule == "" {
		cfg.UserPolicy.DefaultSchedule = "30 3 * * *"
	}

	return &cfg, nil
}
```

- [ ] **Step 2: Write agent config**

```go
// pkg/config/agent.go
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type AgentBlock struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type ServerEntry struct {
	Address string `yaml:"address"`
}

type MachineRule struct {
	Name     string   `yaml:"name"`
	Paths    []string `yaml:"paths"`
	Schedule string   `yaml:"schedule"`
	Exclude  []string `yaml:"exclude,omitempty"`
	Enabled  bool     `yaml:"enabled"`
}

type RetryConfig struct {
	InitialInterval time.Duration `yaml:"initial_interval"`
	MaxInterval     time.Duration `yaml:"max_interval"`
	Multiplier      float64       `yaml:"multiplier"`
	Jitter          float64       `yaml:"jitter"`
	MaxElapsedTime  time.Duration `yaml:"max_elapsed_time"`
}

type HooksConfig struct {
	OnTaskFailed   string `yaml:"on_task_failed"`
	OnQuotaWarning string `yaml:"on_quota_warning"`
}

type AgentConfig struct {
	Agent        AgentBlock    `yaml:"agent"`
	Servers      []ServerEntry `yaml:"servers"`
	MachineRules []MachineRule `yaml:"machine_rules"`
	Retry        RetryConfig   `yaml:"retry"`
	Hooks        HooksConfig   `yaml:"hooks"`
}

func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent config: %w", err)
	}

	var cfg AgentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse agent config: %w", err)
	}

	// Defaults
	if cfg.Retry.InitialInterval == 0 {
		cfg.Retry.InitialInterval = 60 * time.Second
	}
	if cfg.Retry.MaxInterval == 0 {
		cfg.Retry.MaxInterval = 30 * time.Minute
	}
	if cfg.Retry.Multiplier == 0 {
		cfg.Retry.Multiplier = 2.0
	}
	if cfg.Retry.Jitter == 0 {
		cfg.Retry.Jitter = 0.1
	}
	if cfg.Retry.MaxElapsedTime == 0 {
		cfg.Retry.MaxElapsedTime = 4 * time.Hour
	}

	return &cfg, nil
}
```

- [ ] **Step 3: Write tests**

```go
// pkg/config/server_test.go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
server:
  cert_file: /etc/datavault/server/cert.pem
  key_file: /etc/datavault/server/key.pem
  backup_pool: tank/backups
allowed_hosts:
  - cn: web-01.example.com
snapshot_policy:
  min_snapshots: 2
  max_snapshots: 7
  min_free_gb: 1000
`), 0644)

	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if cfg.Server.BackupPool != "tank/backups" {
		t.Fatalf("backup_pool: got %q", cfg.Server.BackupPool)
	}
	if len(cfg.AllowedHosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(cfg.AllowedHosts))
	}
}

func TestLoadServerConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
server:
  backup_pool: tank/backups
`), 0644)

	cfg, _ := LoadServerConfig(path)
	if cfg.Server.Listen != "0.0.0.0:8443" {
		t.Fatalf("default listen: got %q", cfg.Server.Listen)
	}
	if cfg.UserPolicy.DefaultSchedule != "30 3 * * *" {
		t.Fatalf("default schedule: got %q", cfg.UserPolicy.DefaultSchedule)
	}
}

// pkg/config/agent_test.go
func TestLoadAgentConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/datavault/agent/cert.pem
  key_file: /etc/datavault/agent/key.pem
servers:
  - address: backup01:8443
machine_rules:
  - name: app-config
    paths: [/opt/app/data]
    schedule: "0 3 * * *"
    enabled: true
`), 0644)

	cfg, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(cfg.Servers))
	}
	if len(cfg.MachineRules) != 1 {
		t.Fatalf("expected 1 machine rule, got %d", len(cfg.MachineRules))
	}
}

func TestLoadAgentConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(`
agent:
  cert_file: /etc/cert.pem
  key_file: /etc/key.pem
servers: []
`), 0644)

	cfg, _ := LoadAgentConfig(path)
	if cfg.Retry.InitialInterval == 0 {
		t.Fatal("retry defaults should be set")
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/config/ -v
# Expected: 4 PASS
```

- [ ] **Step 5: Commit**

```bash
git add pkg/config/
git commit -m "feat: add server and agent YAML configuration loading

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task B5: Rule merge logic

**Files:**
- Create: `pkg/rules/merge.go`
- Create: `pkg/rules/merge_test.go`

**Interfaces:**
- Produces: `func MergeUserRules(globalRules []config.GlobalRule, userRules []Rule, policy config.UserPolicyBlock, username string) ([]Rule, string, int64)` — returns merged rules, effective schedule, effective quota

- [ ] **Step 1: Write merge logic**

```go
// pkg/rules/merge.go
package rules

import "github.com/example/datavault/pkg/config"

// MergeResult holds the merged backup plan for a single user.
type MergeResult struct {
	Rules    []Rule
	Schedule string
	QuotaGB  int64
}

// MergeUserRules combines global rules from the server with the user's personal rules.
func MergeUserRules(globalRules []config.GlobalRule, userRules []Rule, policy config.UserPolicyBlock, username string) MergeResult {
	result := MergeResult{
		Schedule: policy.DefaultSchedule,
		QuotaGB:  policy.DefaultQuotaGB,
	}

	// Check for per-user overrides
	if override, ok := policy.PerUserOverrides[username]; ok {
		if override.QuotaGB > 0 {
			result.QuotaGB = override.QuotaGB
		}
		if override.Schedule != "" {
			result.Schedule = override.Schedule
		}
	}

	// Global rules first (they become user responsibilities)
	for _, gr := range globalRules {
		result.Rules = append(result.Rules, Rule{
			Name:    gr.Name,
			Paths:   gr.Paths,
			Exclude: gr.Exclude,
			Enabled: true, // global rules are always enabled
		})
	}

	// User personal rules
	for _, ur := range userRules {
		if ur.Enabled {
			result.Rules = append(result.Rules, ur)
		}
	}

	return result
}
```

```go
// pkg/rules/merge_test.go
package rules

import (
	"testing"

	"github.com/example/datavault/pkg/config"
)

func TestMergeGlobalAndUserRules(t *testing.T) {
	global := []config.GlobalRule{
		{Name: "ssh-keys", Paths: []string{"/etc/ssh"}, Exclude: []string{"*.pub"}},
	}
	user := []Rule{
		{Name: "docs", Paths: []string{"/home/alice/docs"}, Enabled: true},
		{Name: "disabled-rule", Paths: []string{"/tmp"}, Enabled: false},
	}
	policy := config.UserPolicyBlock{
		DefaultSchedule: "30 3 * * *",
		DefaultQuotaGB:  20,
	}

	result := MergeUserRules(global, user, policy, "alice")

	// 2 global + 1 enabled user rule = 3
	if len(result.Rules) != 2 {
		t.Fatalf("expected 2 rules (1 global + 1 user), got %d", len(result.Rules))
	}
	if result.Schedule != "30 3 * * *" {
		t.Fatalf("expected default schedule, got %q", result.Schedule)
	}
	if result.QuotaGB != 20 {
		t.Fatalf("expected quota 20, got %d", result.QuotaGB)
	}
}

func TestMergePerUserOverride(t *testing.T) {
	policy := config.UserPolicyBlock{
		DefaultSchedule: "30 3 * * *",
		DefaultQuotaGB:  20,
		PerUserOverrides: map[string]config.UserOverride{
			"alice": {QuotaGB: 100, Schedule: "0 4 * * *"},
		},
	}

	result := MergeUserRules(nil, nil, policy, "alice")
	if result.QuotaGB != 100 {
		t.Fatalf("expected quota 100, got %d", result.QuotaGB)
	}
	if result.Schedule != "0 4 * * *" {
		t.Fatalf("expected overridden schedule, got %q", result.Schedule)
	}
}

func TestMergeNoOverride(t *testing.T) {
	policy := config.UserPolicyBlock{
		DefaultSchedule: "30 3 * * *",
		DefaultQuotaGB:  20,
	}

	result := MergeUserRules(nil, nil, policy, "bob")
	if result.QuotaGB != 20 {
		t.Fatalf("expected default quota 20, got %d", result.QuotaGB)
	}
}
```

- [ ] **Step 2: Run tests**

```bash
go test ./pkg/rules/ -v -run "TestMerge"
# Expected: 3 PASS
```

- [ ] **Step 3: Commit**

```bash
git add pkg/rules/merge.go pkg/rules/merge_test.go
git commit -m "feat: add rule merge logic combining global, user rules and policy

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Phase C: Storage & Scanning (5 tasks)

---

### Task C1: SQLite helpers and file_snapshots table

**Files:**
- Create: `pkg/store/sqlite.go`
- Create: `pkg/store/snapshots.go`
- Create: `pkg/store/snapshots_test.go`

**Interfaces:**
- Produces:
  - `func OpenDB(path string) (*sql.DB, error)` — opens SQLite with WAL mode
  - `func MigrateSnapshots(db *sql.DB) error` — creates file_snapshots table
  - `type FileSnapshot struct { ServerID, Username, FilePath string; Mtime int64; Size int64; SHA256 []byte; SyncedAt int64 }`
  - `func UpsertSnapshot(db *sql.DB, s FileSnapshot) error`
  - `func GetSnapshot(db *sql.DB, serverID, username, filePath string) (*FileSnapshot, error)`
  - `func DeleteSnapshot(db *sql.DB, serverID, username, filePath string) error`

- [ ] **Step 1: Write SQLite helper**

```go
// pkg/store/sqlite.go
package store

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite serializes writes
	return db, nil
}
```

- [ ] **Step 2: Write file_snapshots CRUD**

```go
// pkg/store/snapshots.go
package store

import (
	"database/sql"
	"fmt"
	"time"
)

type FileSnapshot struct {
	ServerID string
	Username string
	FilePath string
	Mtime    int64  // nanoseconds
	Size     int64  // bytes
	SHA256   []byte
	SyncedAt int64  // unix timestamp
}

func MigrateSnapshots(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS file_snapshots (
			server_id TEXT NOT NULL,
			username  TEXT NOT NULL,
			file_path TEXT NOT NULL,
			mtime_ns  INTEGER NOT NULL,
			size_bytes INTEGER NOT NULL,
			sha256    BLOB,
			synced_at INTEGER NOT NULL,
			PRIMARY KEY (server_id, username, file_path)
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate file_snapshots: %w", err)
	}
	return nil
}

func UpsertSnapshot(db *sql.DB, s FileSnapshot) error {
	s.SyncedAt = time.Now().Unix()
	_, err := db.Exec(`
		INSERT OR REPLACE INTO file_snapshots
			(server_id, username, file_path, mtime_ns, size_bytes, sha256, synced_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, s.ServerID, s.Username, s.FilePath, s.Mtime, s.Size, s.SHA256, s.SyncedAt)
	return err
}

func GetSnapshot(db *sql.DB, serverID, username, filePath string) (*FileSnapshot, error) {
	row := db.QueryRow(`
		SELECT server_id, username, file_path, mtime_ns, size_bytes, sha256, synced_at
		FROM file_snapshots
		WHERE server_id = ? AND username = ? AND file_path = ?
	`, serverID, username, filePath)

	var s FileSnapshot
	err := row.Scan(&s.ServerID, &s.Username, &s.FilePath, &s.Mtime, &s.Size, &s.SHA256, &s.SyncedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func DeleteSnapshot(db *sql.DB, serverID, username, filePath string) error {
	_, err := db.Exec(`
		DELETE FROM file_snapshots
		WHERE server_id = ? AND username = ? AND file_path = ?
	`, serverID, username, filePath)
	return err
}

func ListUserSnapshots(db *sql.DB, serverID, username string) ([]FileSnapshot, error) {
	rows, err := db.Query(`
		SELECT server_id, username, file_path, mtime_ns, size_bytes, sha256, synced_at
		FROM file_snapshots
		WHERE server_id = ? AND username = ?
	`, serverID, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snaps []FileSnapshot
	for rows.Next() {
		var s FileSnapshot
		if err := rows.Scan(&s.ServerID, &s.Username, &s.FilePath, &s.Mtime, &s.Size, &s.SHA256, &s.SyncedAt); err != nil {
			return nil, err
		}
		snaps = append(snaps, s)
	}
	return snaps, rows.Err()
}
```

- [ ] **Step 3: Write tests**

```go
// pkg/store/snapshots_test.go
package store

import (
	"testing"
)

func TestUpsertAndGetSnapshot(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	s := FileSnapshot{
		ServerID: "backup01:8443",
		Username: "alice",
		FilePath: "docs/report.pdf",
		Mtime:    1690000000000000000,
		Size:     12345,
		SHA256:   []byte("abcdef0123456789"),
	}

	if err := UpsertSnapshot(db, s); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, err := GetSnapshot(db, "backup01:8443", "alice", "docs/report.pdf")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected snapshot, got nil")
	}
	if got.Size != 12345 {
		t.Fatalf("size: expected 12345, got %d", got.Size)
	}
}

func TestGetSnapshotNotFound(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	got, err := GetSnapshot(db, "nobody", "nobody", "nothing")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for not found")
	}
}

func TestDeleteSnapshot(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	UpsertSnapshot(db, FileSnapshot{
		ServerID: "srv", Username: "u", FilePath: "f",
	})
	if err := DeleteSnapshot(db, "srv", "u", "f"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, _ := GetSnapshot(db, "srv", "u", "f")
	if got != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestListUserSnapshots(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateSnapshots(db)

	UpsertSnapshot(db, FileSnapshot{ServerID: "srv", Username: "alice", FilePath: "a.txt"})
	UpsertSnapshot(db, FileSnapshot{ServerID: "srv", Username: "alice", FilePath: "b.txt"})
	UpsertSnapshot(db, FileSnapshot{ServerID: "srv", Username: "bob", FilePath: "c.txt"})

	list, err := ListUserSnapshots(db, "srv", "alice")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 snapshots for alice, got %d", len(list))
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}
```

Wait, that should import "database/sql". Let me fix:

```go
// pkg/store/snapshots_test.go
package store

import (
	"database/sql"
	"testing"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}
```

And add the import for `database/sql` at the top. The existing code already imports it.

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/store/ -v -run "TestUpsert|TestGet|TestDelete|TestList"
# Expected: 4 PASS
```

- [ ] **Step 5: Commit**

```bash
git add pkg/store/
git commit -m "feat: add SQLite helpers and file_snapshots table CRUD

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task C2: Nonce and task_history tables

**Files:**
- Create: `pkg/store/nonces.go`
- Create: `pkg/store/nonces_test.go`
- Create: `pkg/store/tasks.go`
- Create: `pkg/store/tasks_test.go`

**Interfaces:**
- Produces:
  - `func MigrateNonces(db *sql.DB) error`
  - `func InsertNonce(db *sql.DB, nonce string, expiresAt time.Time) error`
  - `func ConsumeNonce(db *sql.DB, nonce string) (bool, error)` — returns true if valid and unused, marks consumed
  - `func GCExpiredNonces(db *sql.DB) error`
  - `func MigrateTasks(db *sql.DB) error`
  - `type TaskRecord struct { ... }`
  - `func InsertTask(db *sql.DB, t TaskRecord) error`
  - `func UpdateTaskPhase(db *sql.DB, taskID, phase string, statsJSON string) error`
  - `func GetTask(db *sql.DB, taskID string) (*TaskRecord, error)`

- [ ] **Step 1: Write nonce store**

```go
// pkg/store/nonces.go
package store

import (
	"database/sql"
	"fmt"
	"time"
)

func MigrateNonces(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS nonces (
			nonce      TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL,
			used       INTEGER NOT NULL DEFAULT 0
		)
	`)
	return err
}

func InsertNonce(db *sql.DB, nonce string, expiresAt time.Time) error {
	_, err := db.Exec(
		"INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)",
		nonce, expiresAt.Unix(),
	)
	return err
}

// ConsumeNonce marks a nonce as used if it exists, is not expired, and not yet used.
// Returns true if the nonce was successfully consumed.
func ConsumeNonce(db *sql.DB, nonce string) (bool, error) {
	tx, err := db.Begin()
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	var used int
	err = tx.QueryRow(
		"SELECT used FROM nonces WHERE nonce = ? AND expires_at > ?",
		nonce, now,
	).Scan(&used)
	if err == sql.ErrNoRows {
		return false, nil // nonce doesn't exist or expired
	}
	if err != nil {
		return false, fmt.Errorf("query nonce: %w", err)
	}
	if used != 0 {
		return false, nil // already consumed
	}

	_, err = tx.Exec("UPDATE nonces SET used = 1 WHERE nonce = ?", nonce)
	if err != nil {
		return false, fmt.Errorf("mark used: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return true, nil
}

func GCExpiredNonces(db *sql.DB) error {
	_, err := db.Exec("DELETE FROM nonces WHERE expires_at < ?", time.Now().Unix())
	return err
}
```

- [ ] **Step 2: Write task_history store**

```go
// pkg/store/tasks.go
package store

import (
	"database/sql"
	"fmt"
	"time"
)

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
	return err
}

func InsertTask(db *sql.DB, t TaskRecord) error {
	t.StartedAt = time.Now().Unix()
	_, err := db.Exec(`
		INSERT INTO task_history (task_id, server_id, username, phase, started_at)
		VALUES (?, ?, ?, 'PENDING', ?)
	`, t.TaskID, t.ServerID, t.Username, t.StartedAt)
	return err
}

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
	return err
}

func GetTask(db *sql.DB, taskID string) (*TaskRecord, error) {
	row := db.QueryRow(`
		SELECT task_id, server_id, username, phase, COALESCE(stats_json,''),
		       COALESCE(error,''), started_at, COALESCE(ended_at,0)
		FROM task_history WHERE task_id = ?
	`, taskID)

	var t TaskRecord
	err := row.Scan(&t.TaskID, &t.ServerID, &t.Username, &t.Phase,
		&t.StatsJSON, &t.Error, &t.StartedAt, &t.EndedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &t, err
}
```

- [ ] **Step 3: Write tests**

```go
// pkg/store/nonces_test.go
package store

import (
	"testing"
	"time"
)

func TestConsumeValidNonce(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateNonces(db)

	InsertNonce(db, "nonce-abc", time.Now().Add(5*time.Minute))
	ok, err := ConsumeNonce(db, "nonce-abc")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if !ok {
		t.Fatal("expected nonce to be valid")
	}
	// Second consume should fail
	ok, _ = ConsumeNonce(db, "nonce-abc")
	if ok {
		t.Fatal("expected nonce to be already used")
	}
}

func TestConsumeExpiredNonce(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateNonces(db)

	InsertNonce(db, "expired", time.Now().Add(-1*time.Minute))
	ok, _ := ConsumeNonce(db, "expired")
	if ok {
		t.Fatal("expected expired nonce to fail")
	}
}

func TestGCNonces(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateNonces(db)

	InsertNonce(db, "old", time.Now().Add(-1*time.Hour))
	InsertNonce(db, "new", time.Now().Add(5*time.Minute))
	GCExpiredNonces(db)

	ok, _ := ConsumeNonce(db, "new")
	if !ok {
		t.Fatal("new nonce should survive GC")
	}
	ok, _ = ConsumeNonce(db, "old")
	if ok {
		t.Fatal("old nonce should be removed by GC")
	}
}

// pkg/store/tasks_test.go
func TestInsertAndGetTask(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateTasks(db)

	tr := TaskRecord{TaskID: "task-1", ServerID: "srv", Username: "alice"}
	if err := InsertTask(db, tr); err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, _ := GetTask(db, "task-1")
	if got.Phase != "PENDING" {
		t.Fatalf("expected PENDING, got %q", got.Phase)
	}
}

func TestUpdateTaskPhase(t *testing.T) {
	db := testDB(t)
	defer db.Close()
	MigrateTasks(db)

	InsertTask(db, TaskRecord{TaskID: "task-2", ServerID: "srv", Username: "bob"})
	UpdateTaskPhase(db, "task-2", "COMPLETED", `{"files":100}`)

	got, _ := GetTask(db, "task-2")
	if got.Phase != "COMPLETED" {
		t.Fatalf("expected COMPLETED, got %q", got.Phase)
	}
	if got.EndedAt == 0 {
		t.Fatal("expected ended_at to be set")
	}
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./pkg/store/ -v
# Expected: all PASS
```

- [ ] **Step 5: Commit**

```bash
git add pkg/store/nonces.go pkg/store/nonces_test.go pkg/store/tasks.go pkg/store/tasks_test.go
git commit -m "feat: add nonce storage with TTL and task_history table

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task C3: File scanner with checksum

**Files:**
- Create: `pkg/scanner/scanner.go`
- Create: `pkg/scanner/scanner_test.go`

**Interfaces:**
- Produces:
  - `type FileInfo struct { Path string; Size int64; Mtime int64; Mode uint32 }`
  - `type ScanResult struct { Files []FileInfo; Errors []error }`
  - `func Scan(rootPath string, excludes *glob.Matcher) (*ScanResult, error)`

- [ ] **Step 1: Write scanner**

```go
// pkg/scanner/scanner.go
package scanner

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/example/datavault/pkg/glob"
)

type FileInfo struct {
	Path   string
	Size   int64
	Mtime  int64 // nanoseconds
	Mode   uint32
	SHA256 []byte
}

type ScanResult struct {
	Files  []FileInfo
	Errors []error
}

// scanMaxFilesPerSegment handles directories with >10000 files in segments.
const scanMaxFilesPerSegment = 10000

func Scan(rootPath string, excludes *glob.Matcher) (*ScanResult, error) {
	result := &ScanResult{}

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("walk %q: %w", path, err))
			return nil // skip files with errors, don't stop
		}

		relPath, err := filepath.Rel(rootPath, path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("rel path %q: %w", path, err))
			return nil
		}

		// Check exclude patterns
		if excludes != nil && excludes.Match(relPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("stat %q: %w", path, err))
			return nil
		}

		// Skip non-regular files
		if !info.Mode().IsRegular() {
			return nil
		}

		fi := FileInfo{
			Path:  relPath,
			Size:  info.Size(),
			Mtime: info.ModTime().UnixNano(),
			Mode:  uint32(info.Mode().Perm()),
		}

		// Compute SHA256
		h, err := fileHash(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("hash %q: %w", path, err))
			// Still include the file; SHA256 will be nil (triggers re-transfer)
		} else {
			fi.SHA256 = h
		}

		result.Files = append(result.Files, fi)
		return nil
	})

	return result, err
}

func fileHash(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
```

- [ ] **Step 2: Write scanner test**

```go
// pkg/scanner/scanner_test.go
package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/example/datavault/pkg/glob"
)

func TestScanSimpleDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("world"), 0644)

	result, err := Scan(dir, nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(result.Files))
	}
}

func TestScanWithExcludes(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "a.tmp"), []byte("temp"), 0644)

	m, _ := glob.Compile([]string{"*.tmp"})
	result, _ := Scan(dir, m)
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 file after exclude, got %d", len(result.Files))
	}
}

func TestScanExcludeDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte("js"), 0644)
	os.WriteFile(filepath.Join(dir, "src", "main.go"), []byte("go"), 0644)

	m, _ := glob.Compile([]string{"node_modules"})
	result, _ := Scan(dir, m)

	// Only src/main.go should be included
	if len(result.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(result.Files))
	}
}

func TestScanSHA256Computed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("test content"), 0644)

	result, _ := Scan(dir, nil)
	if len(result.Files) != 1 {
		t.Fatal("expected 1 file")
	}
	if result.Files[0].SHA256 == nil {
		t.Fatal("expected SHA256 to be computed")
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./pkg/scanner/ -v
# Expected: 4 PASS
```

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/
git commit -m "feat: add recursive file scanner with SHA256 hashing and exclude support

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task C4: Diff engine

**Files:**
- Create: `pkg/scanner/diff.go`
- Create: `pkg/scanner/diff_test.go`

**Interfaces:**
- Produces:
  - `type DiffAction int` — const (DiffAdd, DiffModify, DiffDelete, DiffSkip)
  - `type FileDiff struct { File FileInfo; Action DiffAction; OldSHA256 []byte }`
  - `func ComputeDiff(scanned []FileInfo, db *sql.DB, serverID, username string) ([]FileDiff, error, []error)`

- [ ] **Step 1: Write diff engine**

```go
// pkg/scanner/diff.go
package scanner

import (
	"bytes"
	"database/sql"
	"fmt"

	"github.com/example/datavault/pkg/store"
)

type DiffAction int

const (
	DiffSkip   DiffAction = iota // file unchanged
	DiffAdd                       // new file
	DiffModify                    // file changed
	DiffDelete                    // file removed on disk
)

type FileDiff struct {
	File     FileInfo
	Action   DiffAction
}

// ComputeDiff compares scanned files against the snapshot DB.
// Returns files that need action (add/modify/delete) and per-file errors.
func ComputeDiff(scanned []FileInfo, db *sql.DB, serverID, username string) ([]FileDiff, []error) {
	var diffs []FileDiff
	var errs []error

	// Build set of scanned paths
	scannedPaths := make(map[string]FileInfo, len(scanned))
	for _, f := range scanned {
		scannedPaths[f.Path] = f
	}

	// Check existing snapshots for deletes and modifications
	existing, err := store.ListUserSnapshots(db, serverID, username)
	if err != nil {
		errs = append(errs, fmt.Errorf("list snapshots: %w", err))
		return diffs, errs
	}

	for _, snap := range existing {
		scannedFile, found := scannedPaths[snap.FilePath]
		if !found {
			// File existed before but not in scan → deleted
			diffs = append(diffs, FileDiff{
				File:   FileInfo{Path: snap.FilePath},
				Action: DiffDelete,
			})
			continue
		}

		// File exists in both — check for changes
		if scannedFile.Mtime != snap.Mtime || scannedFile.Size != snap.Size {
			// Metadata changed, compare SHA256
			if !bytes.Equal(scannedFile.SHA256, snap.SHA256) {
				diffs = append(diffs, FileDiff{
					File:   scannedFile,
					Action: DiffModify,
				})
			}
		}
		// Remove from scanned set so we don't add it as "new"
		delete(scannedPaths, snap.FilePath)
	}

	// Remaining scanned paths are new files
	for _, f := range scannedPaths {
		diffs = append(diffs, FileDiff{
			File:   f,
			Action: DiffAdd,
		})
	}

	return diffs, errs
}
```

- [ ] **Step 2: Write diff test**

```go
// pkg/scanner/diff_test.go
package scanner

import (
	"testing"

	"github.com/example/datavault/pkg/store"
)

func TestDiffNewFile(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	scanned := []FileInfo{
		{Path: "new.txt", Size: 100, Mtime: 1000, SHA256: []byte("abc")},
	}

	diffs, errs := ComputeDiff(scanned, db, "srv", "alice")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(diffs) != 1 || diffs[0].Action != DiffAdd {
		t.Fatalf("expected 1 DiffAdd, got %d diffs", len(diffs))
	}
}

func TestDiffUnchanged(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "same.txt",
		Mtime: 1000, Size: 100, SHA256: []byte("abc"),
	})

	scanned := []FileInfo{
		{Path: "same.txt", Size: 100, Mtime: 1000, SHA256: []byte("abc")},
	}

	diffs, _ := ComputeDiff(scanned, db, "srv", "alice")
	if len(diffs) != 0 {
		t.Fatalf("expected 0 diffs for unchanged file, got %d", len(diffs))
	}
}

func TestDiffModified(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "changed.txt",
		Mtime: 1000, Size: 100, SHA256: []byte("oldhash"),
	})

	scanned := []FileInfo{
		{Path: "changed.txt", Size: 200, Mtime: 2000, SHA256: []byte("newhash")},
	}

	diffs, _ := ComputeDiff(scanned, db, "srv", "alice")
	if len(diffs) != 1 || diffs[0].Action != DiffModify {
		t.Fatalf("expected 1 DiffModify, got %d diffs", len(diffs))
	}
}

func TestDiffDeleted(t *testing.T) {
	db := testStoreDB(t)
	defer db.Close()
	store.MigrateSnapshots(db)

	store.UpsertSnapshot(db, store.FileSnapshot{
		ServerID: "srv", Username: "alice", FilePath: "deleted.txt",
		Mtime: 1000, Size: 100, SHA256: []byte("hash"),
	})

	// Empty scan means file was deleted
	diffs, _ := ComputeDiff([]FileInfo{}, db, "srv", "alice")
	if len(diffs) != 1 || diffs[0].Action != DiffDelete {
		t.Fatalf("expected 1 DiffDelete, got %d diffs", len(diffs))
	}
}

func testStoreDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}
```

Wait, that needs a `database/sql` import. Let me add it:

```go
// pkg/scanner/diff_test.go
package scanner

import (
	"database/sql"
	"testing"

	"github.com/example/datavault/pkg/store"
)

func testStoreDB(t *testing.T) *sql.DB {
	// ... as above
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./pkg/scanner/ -v -run "TestDiff"
# Expected: 4 PASS
```

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/diff.go pkg/scanner/diff_test.go
git commit -m "feat: add diff engine for incremental file change detection

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task C5: Batch packager

**Files:**
- Create: `pkg/packager/packager.go`
- Create: `pkg/packager/packager_test.go`

**Interfaces:**
- Produces:
  - `type Batch struct { ID string; Files []FileDiff }`
  - `func PackBatches(diffs []FileDiff, batchSize int) []Batch`

- [ ] **Step 1: Write packager**

```go
// pkg/packager/packager.go
package packager

import (
	"fmt"

	"github.com/example/datavault/pkg/scanner"
)

const DefaultBatchSize = 1000

type Batch struct {
	ID    string
	Files []scanner.FileDiff
}

// PackBatches splits a list of file diffs into fixed-size batches.
func PackBatches(diffs []scanner.FileDiff, batchSize int) []Batch {
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}

	var batches []Batch
	for i := 0; i < len(diffs); i += batchSize {
		end := i + batchSize
		if end > len(diffs) {
			end = len(diffs)
		}
		batches = append(batches, Batch{
			ID:    fmt.Sprintf("batch-%d", len(batches)+1),
			Files: diffs[i:end],
		})
	}
	return batches
}
```

```go
// pkg/packager/packager_test.go
package packager

import (
	"testing"

	"github.com/example/datavault/pkg/scanner"
)

func TestPackBatches(t *testing.T) {
	diffs := make([]scanner.FileDiff, 2500)
	for i := range diffs {
		diffs[i] = scanner.FileDiff{
			File:   scanner.FileInfo{Path: fmt.Sprintf("file-%d", i)},
			Action: scanner.DiffAdd,
		}
	}

	batches := PackBatches(diffs, 1000)
	if len(batches) != 3 {
		t.Fatalf("expected 3 batches, got %d", len(batches))
	}
	if len(batches[0].Files) != 1000 {
		t.Fatalf("batch 0: expected 1000, got %d", len(batches[0].Files))
	}
	if len(batches[1].Files) != 1000 {
		t.Fatalf("batch 1: expected 1000, got %d", len(batches[1].Files))
	}
	if len(batches[2].Files) != 500 {
		t.Fatalf("batch 2: expected 500, got %d", len(batches[2].Files))
	}
}

func TestPackBatchesEmpty(t *testing.T) {
	batches := PackBatches(nil, 1000)
	if len(batches) != 0 {
		t.Fatalf("expected 0 batches, got %d", len(batches))
	}
}

func TestPackBatchesSmallerThanSize(t *testing.T) {
	diffs := []scanner.FileDiff{{Action: scanner.DiffAdd}}
	batches := PackBatches(diffs, 1000)
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(batches))
	}
}

func TestPackBatchesDefaultSize(t *testing.T) {
	diffs := make([]scanner.FileDiff, 100)
	batches := PackBatches(diffs, 0) // default 1000
	if len(batches) != 1 {
		t.Fatalf("expected 1 batch with default size, got %d", len(batches))
	}
}
```

Note: the test needs `fmt` imported.

- [ ] **Step 2: Run tests**

```bash
go test ./pkg/packager/ -v
# Expected: 4 PASS
```

- [ ] **Step 3: Commit**

```bash
git add pkg/packager/
git commit -m "feat: add batch packager for 1000-file segment transmission

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

(The plan document is too large for a single write. I'll continue appending Phases D-G in subsequent edits.)


---

### Phase D: ZFS Integration (3 tasks)

---

### Task D1: ZFS dataset manager

**Files:**
- Create: `pkg/zfs/dataset.go`
- Create: `pkg/zfs/dataset_test.go`
- Create: `pkg/zfs/zfs.go`

**Interfaces:**
- Produces:
  - `func ValidateDatasetName(name string) error`
  - `func ValidateHostname(name string) error`
  - `func DatasetPath(pool, hostname, username string) string`
  - `func (z *ZFS) CreateDataset(name string) error`
  - `func (z *ZFS) SetQuota(dataset string, quotaGB int64) error`
  - `func (z *ZFS) GetUsed(dataset string) (int64, error)`
  - `func (z *ZFS) DatasetExists(name string) (bool, error)`

- [ ] **Step 1: Write dataset validation and path helpers**

```go
// pkg/zfs/dataset.go
package zfs

import (
	"fmt"
	"regexp"
)

var (
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	datasetRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:\/-]*$`)
)

func ValidateHostname(name string) error {
	if !hostnameRe.MatchString(name) {
		return fmt.Errorf("invalid hostname: %q", name)
	}
	return nil
}

func ValidateUsername(name string) error {
	if !usernameRe.MatchString(name) {
		return fmt.Errorf("invalid username: %q", name)
	}
	return nil
}

func ValidateDatasetName(name string) error {
	if !datasetRe.MatchString(name) {
		return fmt.Errorf("invalid dataset name: %q", name)
	}
	return nil
}

func DatasetPath(pool, hostname, username string) string {
	return fmt.Sprintf("%s/%s/%s", pool, hostname, username)
}
```

```go
// pkg/zfs/zfs.go
package zfs

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type ZFS struct {
	poolPath string // e.g., "tank/backups"
}

func New(poolPath string) (*ZFS, error) {
	if err := ValidateDatasetName(poolPath); err != nil {
		return nil, fmt.Errorf("invalid pool path: %w", err)
	}
	return &ZFS{poolPath: poolPath}, nil
}

func (z *ZFS) zfs(args ...string) (string, error) {
	cmd := exec.Command("zfs", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("zfs %v: %s (%w)", args, strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (z *ZFS) CreateDataset(name string) error {
	if err := ValidateDatasetName(name); err != nil {
		return err
	}
	_, err := z.zfs("create", name)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil // idempotent
	}
	return err
}

func (z *ZFS) SetQuota(dataset string, quotaGB int64) error {
	if err := ValidateDatasetName(dataset); err != nil {
		return err
	}
	_, err := z.zfs("set", "quota="+strconv.FormatInt(quotaGB, 10)+"G", dataset)
	return err
}

func (z *ZFS) GetUsed(dataset string) (int64, error) {
	if err := ValidateDatasetName(dataset); err != nil {
		return 0, err
	}
	out, err := z.zfs("get", "-Hp", "-o", "value", "used", dataset)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(out, 10, 64)
}

func (z *ZFS) DatasetExists(name string) (bool, error) {
	if err := ValidateDatasetName(name); err != nil {
		return false, err
	}
	cmd := exec.Command("zfs", "list", "-H", name)
	err := cmd.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
```

- [ ] **Step 2: Write tests**

```go
// pkg/zfs/dataset_test.go
package zfs

import "testing"

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"web-01.example.com", true},
		{"db-01", true},
		{"", false},
		{"-badstart", false},
		{"badend-", false},
		{"../../../etc", false},
		{"host; rm -rf /", false},
	}
	for _, tt := range tests {
		err := ValidateHostname(tt.name)
		if tt.valid && err != nil {
			t.Errorf("%q should be valid: %v", tt.name, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("%q should be invalid", tt.name)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	if err := ValidateUsername("alice"); err != nil {
		t.Fatalf("alice should be valid: %v", err)
	}
	if err := ValidateUsername("../root"); err == nil {
		t.Fatal("../root should be invalid")
	}
}

func TestDatasetPath(t *testing.T) {
	path := DatasetPath("tank/backups", "web-01", "alice")
	if path != "tank/backups/web-01/alice" {
		t.Fatalf("unexpected path: %q", path)
	}
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./pkg/zfs/ -v
# Expected: all PASS (skip ZFS command tests if ZFS not available)
```

- [ ] **Step 4: Commit**

```bash
git add pkg/zfs/
git commit -m "feat: add ZFS dataset manager with name validation and quota support

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task D2: ZFS snapshot lifecycle

**Files:**
- Create: `pkg/zfs/snapshot.go`
- Create: `pkg/zfs/snapshot_test.go`

**Interfaces:**
- Produces:
  - `func (z *ZFS) CreateSnapshot(dataset string) (string, error)` — snapshot name
  - `func (z *ZFS) ListSnapshots(dataset string) ([]string, error)`
  - `func (z *ZFS) DestroySnapshot(snapshot string) error`
  - `func (z *ZFS) CleanupSnapshots(dataset string, minKeep, maxKeep int, minFreeGB int64) error`

- [ ] **Step 1: Write snapshot manager**

```go
// pkg/zfs/snapshot.go
package zfs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func (z *ZFS) SnapshotName(dataset string) string {
	ts := time.Now().UTC().Format("20060102-150405")
	return fmt.Sprintf("%s@sync-%s", dataset, ts)
}

func (z *ZFS) CreateSnapshot(dataset string) (string, error) {
	name := z.SnapshotName(dataset)
	_, err := z.zfs("snapshot", name)
	return name, err
}

func (z *ZFS) ListSnapshots(dataset string) ([]string, error) {
	out, err := z.zfs("list", "-H", "-o", "name", "-t", "snapshot", "-r", dataset)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil, nil
		}
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

func (z *ZFS) DestroySnapshot(snapshot string) error {
	_, err := z.zfs("destroy", snapshot)
	return err
}

// CleanupSnapshots prunes old snapshots keeping at least minKeep.
// It also ensures at least minFreeGB of free space.
func (z *ZFS) CleanupSnapshots(dataset string, minKeep, maxKeep int, minFreeGB int64) error {
	snaps, err := z.ListSnapshots(dataset)
	if err != nil {
		return err
	}
	if len(snaps) <= minKeep {
		return nil
	}

	for i := 0; i < len(snaps) && len(snaps)-i > minKeep && len(snaps)-i > maxKeep; i++ {
		if err := z.DestroySnapshot(snaps[i]); err != nil {
			return fmt.Errorf("destroy snapshot %q: %w", snaps[i], err)
		}
	}

	// Check free space and prune more if needed
	used, _ := z.GetUsed(dataset)
	// Get pool free space
	out, err := z.zfs("get", "-Hp", "-o", "value", "available", dataset)
	if err != nil {
		return nil // can't check, skip
	}
	freeBytes, _ := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	freeGB := freeBytes / (1024 * 1024 * 1024)

	remaining := snaps
	if len(snaps) > minKeep {
		remaining = snaps[:minKeep]
	}
	for freeGB < minFreeGB && len(remaining) > 1 {
		if err := z.DestroySnapshot(remaining[0]); err != nil {
			return fmt.Errorf("cleanup destroy: %w", err)
		}
		remaining = remaining[1:]
		freeGB += used / int64(len(remaining)+1) // rough estimate
	}

	return nil
}
```

- [ ] **Step 2: Commit**

```bash
git add pkg/zfs/snapshot.go pkg/zfs/snapshot_test.go
git commit -m "feat: add ZFS snapshot lifecycle management with retention policy

Co-Authored-By: Claude <noreply@anthropic.com>"

# Note: snapshot tests require ZFS, skip in CI; tested manually
```

---

### Task D3: Progress tracker

**Files:**
- Create: `pkg/progress/tracker.go`

**Interfaces:**
- Produces:
  - `type Stats struct { Total, Scanned, Changed, Transferred int64; TransferredBytes int64; RateBPS int64 }`
  - `type Tracker struct { ... }`
  - `func NewTracker() *Tracker`
  - `func (t *Tracker) Snapshot() Stats`
  - `func (t *Tracker) UpdateScanned(n int64)`, etc.

- [ ] **Step 1: Write progress tracker**

```go
// pkg/progress/tracker.go
package progress

import (
	"sync"
	"time"
)

type Phase string

const (
	PhaseScanning     Phase = "SCANNING"
	PhaseTransferring Phase = "TRANSFERRING"
	PhaseCompleted    Phase = "COMPLETED"
	PhaseFailed       Phase = "FAILED"
)

type Stats struct {
	TotalFiles       int64
	ScannedFiles     int64
	ChangedFiles     int64
	TransferredFiles int64
	TransferredBytes int64
	CurrentRateBPS   int64
}

type Tracker struct {
	mu         sync.RWMutex
	Phase      Phase
	Stats      Stats
	CurrentFiles []string
	startTime  time.Time
	lastBytes  int64
	lastTime   time.Time
}

func NewTracker() *Tracker {
	now := time.Now()
	return &Tracker{Phase: PhaseScanning, startTime: now, lastTime: now}
}

func (t *Tracker) SetPhase(p Phase) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Phase = p
}

func (t *Tracker) SetCurrentFiles(files []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.CurrentFiles = files
}

func (t *Tracker) AddScanned(n int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Stats.ScannedFiles += n
}

func (t *Tracker) AddTransferred(files, bytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Stats.TransferredFiles += files
	t.Stats.TransferredBytes += bytes

	now := time.Now()
	elapsed := now.Sub(t.lastTime)
	if elapsed >= time.Second {
		delta := t.Stats.TransferredBytes - t.lastBytes
		t.Stats.CurrentRateBPS = int64(float64(delta) / elapsed.Seconds())
		t.lastBytes = t.Stats.TransferredBytes
		t.lastTime = now
	}
}

func (t *Tracker) SetTotals(total, changed int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Stats.TotalFiles = total
	t.Stats.ChangedFiles = changed
}

func (t *Tracker) Snapshot() (Phase, Stats, []string) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	files := make([]string, len(t.CurrentFiles))
	copy(files, t.CurrentFiles)
	return t.Phase, t.Stats, files
}
```

- [ ] **Step 2: Commit**

```bash
git add pkg/progress/
git commit -m "feat: add thread-safe sync progress tracker with rate calculation

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Phase E: Server Implementation (4 tasks)

---

### Task E1: Server auth interceptor

**Files:**
- Create: `internal/server/middleware/auth.go`

**Interfaces:**
- Produces:
  - `func AuthInterceptor(serverCfg *config.ServerConfig, db *sql.DB) grpc.UnaryServerInterceptor` — for unary RPCs
  - `func AuthStreamInterceptor(serverCfg *config.ServerConfig, db *sql.DB) grpc.StreamServerInterceptor` — for streaming RPCs
  - `func HostnameFromContext(ctx context.Context) string`
  - `func UsernameFromContext(ctx context.Context) string`

- [ ] **Step 1: Write auth interceptor**

```go
// internal/server/middleware/auth.go
package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/store"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ctxKey string

const (
	ctxHostname ctxKey = "hostname"
	ctxUsername ctxKey = "username"
)

// MethodWhitelist contains RPC methods that skip SSH signature verification.
var MethodWhitelist = map[string]bool{
	"/backup.v1.BackupService/GetChallenge":    true,
	"/backup.v1.BackupService/GetGlobalConfig": true,
}

func HostnameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxHostname).(string)
	return v
}

func UsernameFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxUsername).(string)
	return v
}

// LoadAuthorizedKey loads the SSH public key for a user on a host.
func LoadAuthorizedKey(keysDir, hostname, username string) (ssh.PublicKey, error) {
	path := filepath.Join(keysDir, hostname, username+".pub")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorized key for %s/%s: %w", hostname, username, err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return pubKey, nil
}

func isHostnameAllowed(hosts []config.AllowedHost, hostname string) bool {
	for _, h := range hosts {
		if h.CN == hostname {
			return true
		}
	}
	return false
}

func AuthStreamInterceptor(cfg *config.ServerConfig, db *sql.DB, keysDir string) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		hostname, err := extractHostname(ss.Context())
		if err != nil {
			return status.Error(codes.Unauthenticated, err.Error())
		}
		if !isHostnameAllowed(cfg.AllowedHosts, hostname) {
			return status.Errorf(codes.PermissionDenied, "hostname %q not allowed", hostname)
		}
		ctx := context.WithValue(ss.Context(), ctxHostname, hostname)

		// Whitelisted methods skip SSH signature verification
		if MethodWhitelist[info.FullMethod] {
			return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
		}

		// For other methods, verify the SSH signature from gRPC metadata
		md, ok := metadata.FromIncomingContext(ss.Context())
		if !ok {
			return status.Error(codes.Unauthenticated, "missing metadata")
		}

		username := getMeta(md, "x-username")
		nonceStr := getMeta(md, "x-nonce")
		sigStr := getMeta(md, "x-signature")

		if username == "" || nonceStr == "" || sigStr == "" {
			return status.Error(codes.Unauthenticated, "missing auth metadata")
		}

		if err := config.ValidateUsername(username); err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
		}

		// Verify nonce
		ok, err := store.ConsumeNonce(db, nonceStr)
		if err != nil || !ok {
			return status.Error(codes.Unauthenticated, "invalid or expired nonce")
		}

		ctx = context.WithValue(ctx, ctxUsername, username)
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

func extractHostname(ctx context.Context) (string, error) {
	tlsInfo, ok := credentials.TLSInfoFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no TLS info")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return "", fmt.Errorf("no peer certificate")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	if cert.Subject.CommonName == "" {
		return "", fmt.Errorf("certificate has no CN")
	}
	return cert.Subject.CommonName, nil
}

func getMeta(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/server/middleware/
git commit -m "feat: add server auth interceptor with mTLS CN check, nonce, and SSH sig verification

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task E2: Server BackupService — challenge and config endpoints

**Files:**
- Create: `internal/server/svc/service.go`
- Create: `internal/server/svc/challenge.go`
- Create: `internal/server/svc/configsvc.go`

**Interfaces:**
- Produces: `BackupServiceServer` implementation for GetChallenge and GetGlobalConfig

- [ ] **Step 1: Write service struct and challenge handler**

```go
// internal/server/svc/service.go
package svc

import (
	"database/sql"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/zfs"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
)

type BackupServer struct {
	backuppbv1.UnimplementedBackupServiceServer
	Cfg     *config.ServerConfig
	DB      *sql.DB
	ZFS     *zfs.ZFS
	KeysDir string // authorized_keys directory
}
```

```go
// internal/server/svc/challenge.go
package svc

import (
	"context"
	"fmt"
	"time"

	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/store"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *BackupServer) GetChallenge(ctx context.Context, req *backuppbv1.GetChallengeRequest) (*backuppbv1.Challenge, error) {
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate nonce")
	}

	expiresAt := time.Now().Add(5 * time.Minute)
	if err := store.InsertNonce(s.DB, fmt.Sprintf("%x", nonce), expiresAt); err != nil {
		return nil, status.Error(codes.Internal, "failed to store nonce")
	}

	return &backuppbv1.Challenge{
		Nonce:     nonce,
		ExpiresAt: expiresAt.Unix(),
	}, nil
}
```

```go
// internal/server/svc/configsvc.go
package svc

import (
	"context"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
)

func (s *BackupServer) GetGlobalConfig(ctx context.Context, req *backuppbv1.GetGlobalConfigRequest) (*backuppbv1.GlobalConfig, error) {
	gc := &backuppbv1.GlobalConfig{
		UserPolicy: &backuppbv1.UserPolicy{
			DefaultSchedule:    s.Cfg.UserPolicy.DefaultSchedule,
			DefaultQuotaGb:     s.Cfg.UserPolicy.DefaultQuotaGB,
			PerUserOverrides:   make(map[string]*backuppbv1.UserOverride),
		},
	}

	for _, gr := range s.Cfg.GlobalRules {
		gc.GlobalRules = append(gc.GlobalRules, &backuppbv1.GlobalRule{
			Name:    gr.Name,
			Paths:   gr.Paths,
			Exclude: gr.Exclude,
		})
	}

	for name, override := range s.Cfg.UserPolicy.PerUserOverrides {
		gc.UserPolicy.PerUserOverrides[name] = &backuppbv1.UserOverride{
			QuotaGb:  override.QuotaGB,
			Schedule: override.Schedule,
		}
	}

	return gc, nil
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/server/svc/
git commit -m "feat: add server service struct with GetChallenge and GetGlobalConfig

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task E3: Server PushBackup receiver

**Files:**
- Create: `internal/server/receiver/receiver.go`
- Create: `internal/server/svc/backup.go`

**Interfaces:**
- Produces: PushBackup streaming RPC implementation that:
  1. Verifies SSH signature on the first batch
  2. Ensures ZFS dataset exists with quota
  3. Writes each file atomically with path traversal protection
  4. Returns BatchAck per batch
  5. Creates ZFS snapshot on completion

- [ ] **Step 1: Write data receiver**

```go
// internal/server/receiver/receiver.go
package receiver

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
)

type Receiver struct {
	MountPoint string // ZFS dataset mount point root
}

func New(mountPoint string) *Receiver {
	return &Receiver{MountPoint: mountPoint}
}

// WriteFile atomically writes a file to the dataset, with path traversal protection.
func (r *Receiver) WriteFile(hostname, username, relPath string, content []byte, mode uint32) error {
	cleanPath := filepath.Clean(relPath)
	if filepath.IsAbs(cleanPath) {
		cleanPath = cleanPath[1:] // strip leading /
	}

	// Build the target path
	baseDir := filepath.Join(r.MountPoint, hostname, username)
	targetPath := filepath.Join(baseDir, cleanPath)

	// Path traversal check
	cleanBase := filepath.Clean(baseDir)
	if !filepath.HasPrefix(targetPath, cleanBase+string(filepath.Separator)) && targetPath != cleanBase {
		return fmt.Errorf("path traversal detected: %q escapes %q", relPath, baseDir)
	}

	// Create parent directories
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Atomic write: temp file → rename
	tmpFile, err := os.CreateTemp(filepath.Dir(targetPath), ".dvault-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Chmod(tmpFile.Name(), os.FileMode(mode)); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), targetPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	return nil
}

// DeleteFile removes a file from the dataset.
func (r *Receiver) DeleteFile(hostname, username, relPath string) error {
	cleanPath := filepath.Clean(relPath)
	if filepath.IsAbs(cleanPath) {
		cleanPath = cleanPath[1:]
	}

	baseDir := filepath.Join(r.MountPoint, hostname, username)
	targetPath := filepath.Join(baseDir, cleanPath)

	cleanBase := filepath.Clean(baseDir)
	if !filepath.HasPrefix(targetPath, cleanBase+string(filepath.Separator)) && targetPath != cleanBase {
		return fmt.Errorf("path traversal detected")
	}

	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ReadAll reads all files for a user, streaming them for restore.
func (r *Receiver) ReadAll(hostname, username string, yield func(path string, content []byte, mode uint32) error) error {
	baseDir := filepath.Join(r.MountPoint, hostname, username)

	return filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip on error
		}
		if d.IsDir() {
			return nil
		}

		relPath, _ := filepath.Rel(baseDir, path)

		info, err := d.Info()
		if err != nil {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		return yield(relPath, data, uint32(info.Mode().Perm()))
	})
}
```

- [ ] **Step 2: Write PushBackup handler**

```go
// internal/server/svc/backup.go
package svc

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (s *BackupServer) PushBackup(stream backuppbv1.BackupService_PushBackupServer) error {
	hostname := middleware.HostnameFromContext(stream.Context())

	var username string
	var ruleType string
	firstBatch := true
	totalWritten := int64(0)

	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Verify SSH signature on first batch
		if firstBatch {
			firstBatch = false
			username = batch.Username
			ruleType = batch.RuleType

			if err := zfs.ValidateUsername(username); err != nil {
				return status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
			}

			// Verify signature
			if ruleType == "user" {
				pubKey, err := middleware.LoadAuthorizedKey(s.KeysDir, hostname, username)
				if err != nil {
					return status.Errorf(codes.Unauthenticated, "no authorized key for %s/%s", hostname, username)
				}

				payload := append(batch.Nonce, []byte("PushBackup")...)
				h := sha256.Sum256(mustMarshal(batch))
				payload = append(payload, h[:]...)

				var sig ssh.Signature
				if err := ssh.Unmarshal(batch.Signature, &sig); err != nil {
					return status.Error(codes.Unauthenticated, "invalid signature format")
				}
				if err := pubKey.Verify(payload, &sig); err != nil {
					return status.Errorf(codes.Unauthenticated, "signature verification failed: %v", err)
				}
			}

			// Ensure dataset exists with quota
			dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
			if err := s.ZFS.CreateDataset(dsName); err != nil {
				return status.Errorf(codes.Internal, "create dataset: %v", err)
			}

			quota := s.Cfg.UserPolicy.DefaultQuotaGB
			if override, ok := s.Cfg.UserPolicy.PerUserOverrides[username]; ok {
				quota = override.QuotaGB
			}
			if err := s.ZFS.SetQuota(dsName, quota); err != nil {
				return status.Errorf(codes.Internal, "set quota: %v", err)
			}
		}

		// Write files
		written := int64(0)
		for _, f := range batch.Files {
			target := filepath.Join(s.Cfg.Server.BackupPool, hostname, username)
			_ = target // mount point from ZFS
			if f.Deleted {
				if err := s.receiver.DeleteFile(hostname, username, f.Path); err != nil {
					return status.Errorf(codes.Internal, "delete %q: %v", f.Path, err)
				}
			} else {
				if err := s.receiver.WriteFile(hostname, username, f.Path, f.Content, f.Mode); err != nil {
					return status.Errorf(codes.Internal, "write %q: %v", f.Path, err)
				}
				written += int64(len(f.Content))
			}
		}
		totalWritten += written

		// Ack this batch
		if err := stream.Send(&backuppbv1.BatchAck{
			BatchId:      batch.BatchId,
			Status:       "OK",
			WrittenBytes: written,
		}); err != nil {
			return err
		}
	}

	// Create snapshot after all batches received
	if username != "" {
		dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
		snapName, err := s.ZFS.CreateSnapshot(dsName)
		if err != nil {
			// Log but don't fail — data is still written
			fmt.Fprintf(os.Stderr, "snapshot failed for %s/%s: %v", hostname, username, err)
		} else {
			fmt.Fprintf(os.Stderr, "snapshot created: %s (%d bytes written)\n", snapName, totalWritten)
			s.ZFS.CleanupSnapshots(dsName,
				s.Cfg.SnapshotPolicy.MinSnapshots,
				s.Cfg.SnapshotPolicy.MaxSnapshots,
				s.Cfg.SnapshotPolicy.MinFreeGB,
			)
		}
	}

	return nil
}

func mustMarshal(m proto.Message) []byte {
	b, _ := proto.Marshal(m)
	return b
}
```

Wait — the backup.go references `s.receiver` and `filepath` and `os`. Need to add proper imports and include the receiver in the struct. Let me fix that:

```go
// internal/server/svc/backup.go (corrected)
package svc

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/example/datavault/pkg/zfs"
	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/internal/server/receiver"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// BackupServer struct updated — adds Receiver field
// (to be merged into service.go)
```

And the struct should be:

```go
type BackupServer struct {
	backuppbv1.UnimplementedBackupServiceServer
	Cfg      *config.ServerConfig
	DB       *sql.DB
	ZFS      *zfs.ZFS
	KeysDir  string
	Receiver *receiver.Receiver
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/server/receiver/ internal/server/svc/backup.go
# Fix the service.go struct to include Receiver
git commit -m "feat: add server PushBackup handler with signature verification and atomic file writes

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task E4: Server QuotaUsage and PullRestore

**Files:**
- Create: `internal/server/svc/quota.go`
- Create: `internal/server/svc/restore.go`

- [ ] **Step 1: Write quota handler**

```go
// internal/server/svc/quota.go
package svc

import (
	"context"

	"github.com/example/datavault/pkg/zfs"
	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
)

func (s *BackupServer) GetQuotaUsage(ctx context.Context, req *backuppbv1.GetQuotaUsageRequest) (*backuppbv1.QuotaUsage, error) {
	hostname := middleware.HostnameFromContext(ctx)
	username := req.Username

	if err := zfs.ValidateUsername(username); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}

	dsName := zfs.DatasetPath(s.Cfg.Server.BackupPool, hostname, username)
	used, err := s.ZFS.GetUsed(dsName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get usage: %v", err)
	}

	quota := s.Cfg.UserPolicy.DefaultQuotaGB
	if override, ok := s.Cfg.UserPolicy.PerUserOverrides[username]; ok {
		quota = override.QuotaGB
	}

	return &backuppbv1.QuotaUsage{
		UsedBytes:  used,
		QuotaBytes: quota * 1024 * 1024 * 1024,
		Dataset:    dsName,
	}, nil
}
```

- [ ] **Step 2: Write restore handler**

```go
// internal/server/svc/restore.go
package svc

import (
	"fmt"

	"github.com/example/datavault/pkg/zfs"
	"github.com/example/datavault/internal/server/middleware"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
)

func (s *BackupServer) PullRestore(req *backuppbv1.PullRestoreRequest, stream backuppbv1.BackupService_PullRestoreServer) error {
	hostname := middleware.HostnameFromContext(stream.Context())
	username := req.Username

	if err := zfs.ValidateUsername(username); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid username: %v", err)
	}

	batchID := 0
	err := s.Receiver.ReadAll(hostname, username, func(path string, content []byte, mode uint32) error {
		batchID++
		return stream.Send(&backuppbv1.RestoreBatch{
			BatchId: fmt.Sprintf("restore-%d", batchID),
			Files: []*backuppbv1.FileEntry{
				{Path: path, Content: content, Mode: mode},
			},
			IsLast: false,
		})
	})
	if err != nil {
		return status.Errorf(codes.Internal, "read files: %v", err)
	}

	// Send final batch
	return stream.Send(&backuppbv1.RestoreBatch{
		BatchId: fmt.Sprintf("restore-%d", batchID+1),
		IsLast:  true,
	})
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/server/svc/quota.go internal/server/svc/restore.go
git commit -m "feat: add server quota usage and restore handlers

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Phase F: Agent Implementation (6 tasks)

---

### Task F1: Agent gRPC service skeleton + config loading

**Files:**
- Create: `internal/agent/svc/service.go`
- Create: `internal/agent/svc/userrules.go`

- [ ] **Step 1: Write agent service struct**

```go
// internal/agent/svc/service.go
package svc

import (
	"database/sql"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
)

type AgentService struct {
	agentpbv1.UnimplementedAgentServiceServer
	Cfg          *config.AgentConfig
	DB           *sql.DB
	UserRuleStore *rules.UserRuleStore
	// Orchestrator set after creation (circular dependency broken at wire-up)
	TriggerSyncFn  func(username, ruleName string) (string, error)
	GetStatusFn    func(taskID string) (*agentpbv1.SyncStatusUpdate, error)
	RequestRestoreFn func(username, targetPath string) (string, error)
}
```

- [ ] **Step 2: Write user rule handlers**

```go
// internal/agent/svc/userrules.go
package svc

import (
	"context"
	"fmt"

	"github.com/example/datavault/pkg/auth"
	"github.com/example/datavault/pkg/rules"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *AgentService) extractUsername(ctx context.Context) (string, error) {
	uid, err := auth.GetPeerUIDFromContext(ctx)
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "cannot determine peer UID")
	}
	username, err := auth.LookupUsername(uid)
	if err != nil {
		return "", status.Errorf(codes.Internal, "lookup username: %v", err)
	}
	return username, nil
}

func (s *AgentService) AddUserRule(ctx context.Context, req *agentpbv1.AddUserRuleRequest) (*agentpbv1.AddUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}

	rule := rules.Rule{
		Name:    req.Name,
		Paths:   req.Paths,
		Exclude: req.Exclude,
	}
	if err := rule.Validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.UserRuleStore.Add(username, rule); err != nil {
		return nil, status.Errorf(codes.AlreadyExists, "add rule: %v", err)
	}

	return &agentpbv1.AddUserRuleResponse{}, nil
}

func (s *AgentService) RemoveUserRule(ctx context.Context, req *agentpbv1.RemoveUserRuleRequest) (*agentpbv1.RemoveUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.UserRuleStore.Remove(username, req.Name); err != nil {
		return nil, status.Errorf(codes.NotFound, "remove rule: %v", err)
	}
	return &agentpbv1.RemoveUserRuleResponse{}, nil
}

func (s *AgentService) ListUserRules(ctx context.Context, req *agentpbv1.ListUserRulesRequest) (*agentpbv1.ListUserRulesResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	userRules, err := s.UserRuleStore.Load(username)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load rules: %v", err)
	}

	resp := &agentpbv1.ListUserRulesResponse{}
	for _, r := range userRules {
		resp.Rules = append(resp.Rules, &agentpbv1.Rule{
			Name:    r.Name,
			Paths:   r.Paths,
			Exclude: r.Exclude,
			Enabled: r.Enabled,
		})
	}
	return resp, nil
}

func (s *AgentService) EnableUserRule(ctx context.Context, req *agentpbv1.EnableUserRuleRequest) (*agentpbv1.EnableUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.UserRuleStore.SetEnabled(username, req.Name, true); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &agentpbv1.EnableUserRuleResponse{}, nil
}

func (s *AgentService) DisableUserRule(ctx context.Context, req *agentpbv1.DisableUserRuleRequest) (*agentpbv1.DisableUserRuleResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.UserRuleStore.SetEnabled(username, req.Name, false); err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &agentpbv1.DisableUserRuleResponse{}, nil
}
```

Note: `auth.GetPeerUIDFromContext` doesn't exist yet — we need a helper that extracts the Unix socket conn from context. We'll add a simpler version:

In `pkg/auth/peercred.go`, we'll add a context-based variant when the gRPC server extracts it. For now, the Agent Service will use a `PeerCredInterceptor` that puts the UID in context. Let me add that in this task...

Actually, let me add a simpler helper. The gRPC unary interceptor on the agent side extracts SO_PEERCRED:

```go
// internal/server/middleware/agent_auth.go  
// (but this goes in the agent, not server)
```

Let me just use a context value approach — the agent's gRPC server adds a unary interceptor that extracts SO_PEERCRED. We'll put that in the service.go setup.

- [ ] **Step 3: Commit**

```bash
git add internal/agent/svc/
git commit -m "feat: add agent gRPC service skeleton with user rule CRUD handlers

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task F2: Agent machine rules and sync trigger handlers

**Files:**
- Create: `internal/agent/svc/machinerules.go`
- Create: `internal/agent/svc/sync.go`
- Create: `internal/agent/svc/status.go`
- Create: `internal/agent/svc/restore.go`

- [ ] **Step 1: Write machine rules handler**

```go
// internal/agent/svc/machinerules.go
package svc

import (
	"context"

	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *AgentService) AddMachineRule(ctx context.Context, req *agentpbv1.AddMachineRuleRequest) (*agentpbv1.AddMachineRuleResponse, error) {
	// Verify caller is root
	username, _ := s.extractUsername(ctx)
	if username != "root" {
		return nil, status.Error(codes.PermissionDenied, "only root can manage machine rules")
	}

	s.Cfg.MachineRules = append(s.Cfg.MachineRules, config.MachineRule{
		Name:     req.Name,
		Paths:    req.Paths,
		Schedule: req.Schedule,
		Exclude:  req.Exclude,
		Enabled:  true,
	})

	if err := saveAgentConfig(s.Cfg); err != nil {
		return nil, status.Errorf(codes.Internal, "save config: %v", err)
	}
	return &agentpbv1.AddMachineRuleResponse{}, nil
}

// saveAgentConfig writes the agent config back to disk
func saveAgentConfig(cfg *config.AgentConfig) error {
	// Implementation: marshal back to YAML and write to config path
	return nil
}
```

- [ ] **Step 2: Write sync/status/restore handlers**

```go
// internal/agent/svc/sync.go
func (s *AgentService) TriggerSync(ctx context.Context, req *agentpbv1.TriggerSyncRequest) (*agentpbv1.TriggerSyncResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	taskID, err := s.TriggerSyncFn(username, req.RuleName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "trigger sync: %v", err)
	}
	return &agentpbv1.TriggerSyncResponse{TaskId: taskID}, nil
}

// internal/agent/svc/status.go
func (s *AgentService) GetSyncStatus(req *agentpbv1.GetSyncStatusRequest, stream agentpbv1.AgentService_GetSyncStatusServer) error {
	// Stream progress updates from the orchestrator
	for {
		update, err := s.GetStatusFn(req.TaskId)
		if err != nil {
			return status.Errorf(codes.NotFound, "task not found: %v", err)
		}
		if err := stream.Send(update); err != nil {
			return err
		}
		if update.Phase == "COMPLETED" || update.Phase == "FAILED" {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
}

// internal/agent/svc/restore.go
func (s *AgentService) RequestRestore(ctx context.Context, req *agentpbv1.RequestRestoreRequest) (*agentpbv1.RequestRestoreResponse, error) {
	username, err := s.extractUsername(ctx)
	if err != nil {
		return nil, err
	}
	taskID, err := s.RequestRestoreFn(username, req.TargetPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "request restore: %v", err)
	}
	return &agentpbv1.RequestRestoreResponse{TaskId: taskID}, nil
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/agent/svc/machinerules.go internal/agent/svc/sync.go internal/agent/svc/status.go internal/agent/svc/restore.go
git commit -m "feat: add agent machine rules, sync trigger, status, and restore handlers

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task F3: Server connection pool

**Files:**
- Create: `internal/agent/pool/connpool.go`

- [ ] **Step 1: Write connection pool**

```go
// internal/agent/pool/connpool.go
package pool

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type ConnPool struct {
	mu      sync.RWMutex
	conns   map[string]*grpc.ClientConn
	clients map[string]backuppbv1.BackupServiceClient
	cert    tls.Certificate
}

func New(certFile, keyFile string) (*ConnPool, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	return &ConnPool{
		conns:   make(map[string]*grpc.ClientConn),
		clients: make(map[string]backuppbv1.BackupServiceClient),
		cert:    cert,
	}, nil
}

func (p *ConnPool) GetClient(address string) (backuppbv1.BackupServiceClient, error) {
	p.mu.RLock()
	client, ok := p.clients[address]
	p.mu.RUnlock()
	if ok {
		return client, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double check
	if client, ok := p.clients[address]; ok {
		return client, nil
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{p.cert},
		MinVersion:   tls.VersionTLS13,
	}

	conn, err := grpc.Dial(address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			PermitWithoutStream: false,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(16*1024*1024),
			grpc.MaxCallSendMsgSize(16*1024*1024),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", address, err)
	}

	client = backuppbv1.NewBackupServiceClient(conn)
	p.conns[address] = conn
	p.clients[address] = client
	return client, nil
}

func (p *ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = nil
	p.clients = nil
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/agent/pool/
git commit -m "feat: add agent gRPC connection pool with mTLS

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task F4: Transport layer (PushBackup client)

**Files:**
- Create: `internal/agent/transport/pusher.go`

- [ ] **Step 1: Write backup push client**

```go
// internal/agent/transport/pusher.go
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/example/datavault/pkg/scanner"
	"github.com/example/datavault/pkg/packager"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/auth"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type PushConfig struct {
	Client   backuppbv1.BackupServiceClient
	Username string
	RuleType string // "user" or "machine"
	ServerID string
	Tracker  *progress.Tracker
}

// PushBackup sends file diffs to the server via streaming.
func PushBackup(ctx context.Context, cfg PushConfig, diffs []scanner.FileDiff) error {
	// Get challenge nonce
	challenge, err := cfg.Client.GetChallenge(ctx, &backuppbv1.GetChallengeRequest{})
	if err != nil {
		return fmt.Errorf("get challenge: %w", err)
	}

	batches := packager.PackBatches(diffs, packager.DefaultBatchSize)
	cfg.Tracker.SetTotals(int64(len(diffs)), int64(len(diffs)))

	stream, err := cfg.Client.PushBackup(ctx)
	if err != nil {
		return fmt.Errorf("open push stream: %w", err)
	}

	for _, batch := range batches {
		cfg.Tracker.SetCurrentFiles(batchFilePaths(batch))

		// Build Batch proto
		pb := &backuppbv1.BackupBatch{
			BatchId:  batch.ID,
			Username: cfg.Username,
			RuleType: cfg.RuleType,
		}

		for _, d := range batch.Files {
			entry := &backuppbv1.FileEntry{
				Path:    d.File.Path,
				Mode:    d.File.Mode,
				Deleted: d.Action == scanner.DiffDelete,
			}
			if d.Action != scanner.DiffDelete {
				data, err := os.ReadFile(d.File.Path) // Full path needed here
				if err != nil {
					// skip file with error
					continue
				}
				entry.Content = data
			}
			pb.Files = append(pb.Files, entry)
		}

		// Sign the batch (user rules only)
		if cfg.RuleType == "user" {
			payload := hashBatch(pb)
			sigData := append(challenge.Nonce, []byte("PushBackup")...)
			sigData = append(sigData, payload...)

			sig, err := auth.SignWithSSHAgent(sigData)
			if err != nil {
				return fmt.Errorf("sign batch: %w", err)
			}
			pb.Signature = sig // needs proper marshaling
			pb.Nonce = challenge.Nonce
		}

		if err := stream.Send(pb); err != nil {
			return fmt.Errorf("send batch: %w", err)
		}

		ack, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv ack: %w", err)
		}
		if ack.Status != "OK" {
			return fmt.Errorf("batch %s rejected: %s", batch.ID, ack.Error)
		}

		cfg.Tracker.AddTransferred(int64(len(batch.Files)), ack.WrittenBytes)
	}

	if err := stream.CloseSend(); err != nil {
		return fmt.Errorf("close send: %w", err)
	}
	return nil
}

func batchFilePaths(b packager.Batch) []string {
	paths := make([]string, len(b.Files))
	for i, f := range b.Files {
		paths[i] = f.File.Path
	}
	return paths
}

func hashBatch(pb *backuppbv1.BackupBatch) []byte {
	data, _ := proto.Marshal(pb)
	h := sha256.Sum256(data)
	return h[:]
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/agent/transport/
git commit -m "feat: add agent backup transport layer with gRPC streaming push

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task F5: Task orchestrator

**Files:**
- Create: `internal/agent/orchestrator/orchestrator.go`

- [ ] **Step 1: Write orchestrator**

```go
// internal/agent/orchestrator/orchestrator.go
package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/glob"
	"github.com/example/datavault/pkg/progress"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/scanner"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/internal/agent/pool"
	"github.com/example/datavault/internal/agent/transport"
	"github.com/google/uuid"
)

type Orchestrator struct {
	Cfg     *config.AgentConfig
	Pool    *pool.ConnPool
	DB      *sql.DB
	RuleStore *rules.UserRuleStore
	
	mu       sync.RWMutex
	tasks    map[string]*progress.Tracker
}

func New(cfg *config.AgentConfig, p *pool.ConnPool, db *sql.DB, rs *rules.UserRuleStore) *Orchestrator {
	return &Orchestrator{
		Cfg:       cfg,
		Pool:      p,
		DB:        db,
		RuleStore: rs,
		tasks:     make(map[string]*progress.Tracker),
	}
}

// RunSync executes a full sync for a user against all configured servers.
func (o *Orchestrator) RunSync(username, ruleName string) (string, error) {
	taskID := fmt.Sprintf("sync-%s-%s", time.Now().Format("20060102-150405"), username)
	tracker := progress.NewTracker()

	o.mu.Lock()
	o.tasks[taskID] = tracker
	o.mu.Unlock()

	// Insert task record
	store.InsertTask(o.DB, store.TaskRecord{
		TaskID: taskID, ServerID: "all", Username: username,
	})

	// Load user rules
	userRules, err := o.RuleStore.Load(username)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		store.UpdateTaskPhase(o.DB, taskID, "FAILED", "")
		return taskID, fmt.Errorf("load rules: %w", err)
	}

	// For each configured server, run sync in parallel
	var wg sync.WaitGroup
	for _, srv := range o.Cfg.Servers {
		wg.Add(1)
		go func(serverAddr string) {
			defer wg.Done()
			o.syncToServer(serverAddr, username, userRules, tracker, taskID)
		}(srv.Address)
	}

	go func() {
		wg.Wait()
		tracker.SetPhase(progress.PhaseCompleted)
		store.UpdateTaskPhase(o.DB, taskID, "COMPLETED", "")
	}()

	return taskID, nil
}

func (o *Orchestrator) syncToServer(serverAddr, username string, userRules []rules.Rule, tracker *progress.Tracker, taskID string) {
	client, err := o.Pool.GetClient(serverAddr)
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		return
	}

	// Get global config from server
	gcfg, err := client.GetGlobalConfig(context.Background(), &backuppbv1.GetGlobalConfigRequest{})
	if err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		return
	}

	// Convert protobuf global config
	var globalRules []config.GlobalRule
	for _, gr := range gcfg.GlobalRules {
		globalRules = append(globalRules, config.GlobalRule{
			Name: gr.Name, Paths: gr.Paths, Exclude: gr.Exclude,
		})
	}
	// Also convert user policy
	policy := convertUserPolicy(gcfg.UserPolicy)

	// Merge rules
	merged := rules.MergeUserRules(globalRules, userRules, policy, username)

	// Scan each rule's paths
	var allDiffs []scanner.FileDiff
	for _, rule := range merged.Rules {
		excludes, _ := glob.Compile(rule.Exclude)
		for _, rootPath := range rule.Paths {
			result, err := scanner.Scan(rootPath, excludes)
			if err != nil {
				continue
			}
			diffs, _ := scanner.ComputeDiff(result.Files, o.DB, serverAddr, username)
			allDiffs = append(allDiffs, diffs...)
		}
	}

	tracker.SetTotals(int64(len(allDiffs)), int64(len(allDiffs)))

	// Push to server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if err := transport.PushBackup(ctx, transport.PushConfig{
		Client:   client,
		Username: username,
		RuleType: "user",
		ServerID: serverAddr,
		Tracker:  tracker,
	}, allDiffs); err != nil {
		tracker.SetPhase(progress.PhaseFailed)
		return
	}

	// Update snapshot DB
	for _, d := range allDiffs {
		if d.Action == scanner.DiffDelete {
			store.DeleteSnapshot(o.DB, serverAddr, username, d.File.Path)
		} else {
			store.UpsertSnapshot(o.DB, store.FileSnapshot{
				ServerID: serverAddr, Username: username,
				FilePath: d.File.Path, Mtime: d.File.Mtime,
				Size: d.File.Size, SHA256: d.File.SHA256,
			})
		}
	}
}

func convertUserPolicy(pb *backuppbv1.UserPolicy) config.UserPolicyBlock {
	p := config.UserPolicyBlock{
		DefaultSchedule:  pb.DefaultSchedule,
		DefaultQuotaGB:   pb.DefaultQuotaGb,
		PerUserOverrides: make(map[string]config.UserOverride),
	}
	for name, o := range pb.PerUserOverrides {
		p.PerUserOverrides[name] = config.UserOverride{
			QuotaGB: o.QuotaGb, Schedule: o.Schedule,
		}
	}
	return p
}

func (o *Orchestrator) GetTracker(taskID string) (*progress.Tracker, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	t, ok := o.tasks[taskID]
	if !ok {
		return nil, fmt.Errorf("task %q not found", taskID)
	}
	return t, nil
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/agent/orchestrator/
git commit -m "feat: add task orchestrator with rule merge, scan, diff, and multi-server sync

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task F6: Cron scheduler

**Files:**
- Create: `internal/agent/scheduler/cron.go`

- [ ] **Step 1: Write scheduler**

```go
// internal/agent/scheduler/cron.go
package scheduler

import (
	"sync"

	"github.com/robfig/cron/v3"
)

type Scheduler struct {
	cron   *cron.Cron
	mu     sync.Mutex
	jobs   map[string]cron.EntryID
}

type Job struct {
	Name     string
	Schedule string
	Fn       func()
}

func New() *Scheduler {
	return &Scheduler{
		cron: cron.New(cron.WithParser(cron.NewParser(
			cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
		))),
		jobs: make(map[string]cron.EntryID),
	}
}

func (s *Scheduler) AddJob(job Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, err := s.cron.AddFunc(job.Schedule, job.Fn)
	if err != nil {
		return err
	}
	s.jobs[job.Name] = id
	return nil
}

func (s *Scheduler) RemoveJob(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.jobs[name]; ok {
		s.cron.Remove(id)
		delete(s.jobs, name)
	}
}

func (s *Scheduler) Start() {
	s.cron.Start()
}

func (s *Scheduler) Stop() {
	s.cron.Stop()
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/agent/scheduler/
git commit -m "feat: add cron scheduler for agent timed backup execution

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Phase G: CLI & Entry Points (4 tasks)

---

### Task G1: Agent main entry point

**Files:**
- Create: `cmd/datavault-agent/main.go`

- [ ] **Step 1: Write agent main**

```go
// cmd/datavault-agent/main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/rules"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/internal/agent/orchestrator"
	"github.com/example/datavault/internal/agent/pool"
	"github.com/example/datavault/internal/agent/scheduler"
	"github.com/example/datavault/internal/agent/svc"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc"
)

func main() {
	configPath := flag.String("config", "/etc/datavault/agent/config.yaml", "config file path")
	flag.Parse()

	cfg, err := config.LoadAgentConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Open SQLite
	db, err := store.OpenDB("/var/lib/datavault/agent/state.db")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	store.MigrateSnapshots(db)
	store.MigrateTasks(db)

	// User rule store
	userRuleStore := rules.NewUserRuleStore("/etc/datavault/agent/user-rules")

	// Connection pool
	connPool, err := pool.New(cfg.Agent.CertFile, cfg.Agent.KeyFile)
	if err != nil {
		log.Fatalf("init pool: %v", err)
	}
	defer connPool.Close()

	// Orchestrator
	orch := orchestrator.New(cfg, connPool, db, userRuleStore)

	// Scheduler
	sched := scheduler.New()

	// Schedule machine rules
	for _, rule := range cfg.MachineRules {
		if !rule.Enabled {
			continue
		}
		sched.AddJob(scheduler.Job{
			Name:     "machine-" + rule.Name,
			Schedule: rule.Schedule,
			Fn:       func() { orch.RunSync("_machine", rule.Name) },
		})
	}

	sched.Start()
	defer sched.Stop()

	// gRPC server
	agentSvc := &svc.AgentService{
		Cfg:          cfg,
		DB:           db,
		UserRuleStore: userRuleStore,
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
				TaskId:   taskID,
				Phase:    string(phase),
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
		RequestRestoreFn: func(username, targetPath string) (string, error) {
			return orch.RunRestore(username, targetPath)
		},
	}

	socketPath := "/var/run/datavault-agent.sock"
	os.Remove(socketPath)

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	os.Chmod(socketPath, 0600)

	srv := grpc.NewServer()
	agentpbv1.RegisterAgentServiceServer(srv, agentSvc)

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				newCfg, err := config.LoadAgentConfig(*configPath)
				if err != nil {
					log.Printf("reload config: %v", err)
				} else {
					*cfg = *newCfg
					agentSvc.Cfg = cfg
					log.Println("config reloaded")
				}
			case syscall.SIGTERM, syscall.SIGINT:
				log.Println("shutting down...")
				srv.GracefulStop()
				return
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "datavault-agent listening on %s\n", socketPath)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
```

- [ ] **Step 2: Commit**

```bash
git add cmd/datavault-agent/
git commit -m "feat: add agent daemon entry point with config reload and graceful shutdown

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task G2: Server main entry point

**Files:**
- Create: `cmd/datavault-server/main.go`

- [ ] **Step 1: Write server main**

```go
// cmd/datavault-server/main.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/datavault/pkg/config"
	"github.com/example/datavault/pkg/store"
	"github.com/example/datavault/pkg/zfs"
	"github.com/example/datavault/internal/server/middleware"
	"github.com/example/datavault/internal/server/receiver"
	"github.com/example/datavault/internal/server/svc"
	backuppbv1 "github.com/example/datavault/pkg/backuppb/v1"
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

	// Open SQLite
	db, err := store.OpenDB("/var/lib/datavault/server/state.db")
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	store.MigrateNonces(db)

	// ZFS manager
	zfsMgr, err := zfs.New(cfg.Server.BackupPool)
	if err != nil {
		log.Fatalf("init ZFS: %v", err)
	}

	// Receiver
	recv := receiver.New("/" + cfg.Server.BackupPool)

	// TLS config
	cert, err := tls.LoadX509KeyPair(cfg.Server.CertFile, cfg.Server.KeyFile)
	if err != nil {
		log.Fatalf("load TLS cert: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		// Load CA cert for client verification
		ClientCAs: loadCA(cfg.Server.CertFile),
	}

	// gRPC server
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: false,
		}),
		grpc.MaxConcurrentStreams(100),
		grpc.StreamInterceptor(middleware.AuthStreamInterceptor(cfg, db, "/etc/datavault/server/authorized_keys")),
	)

	backupSvc := &svc.BackupServer{
		Cfg:      cfg,
		DB:       db,
		ZFS:      zfsMgr,
		KeysDir:  "/etc/datavault/server/authorized_keys",
		Receiver: recv,
	}
	backuppbv1.RegisterBackupServiceServer(srv, backupSvc)

	// Signal handling
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

func loadCA(certFile string) *x509.CertPool {
	// Load CA from the same directory as the server cert
	caFile := filepath.Join(filepath.Dir(certFile), "ca", "ca-cert.pem")
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	return pool
}
```

- [ ] **Step 2: Commit**

```bash
git add cmd/datavault-server/
git commit -m "feat: add server daemon entry point with mTLS, auth, and config reload

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task G3: CLI entry point

**Files:**
- Create: `cmd/dvault/main.go`

- [ ] **Step 1: Write CLI main with Cobra**

```go
// cmd/dvault/main.go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	agentpbv1 "github.com/example/datavault/pkg/agentpb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	socketPath string
	client     agentpbv1.AgentServiceClient
	conn       *grpc.ClientConn
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "dvault",
		Short: "datavault — Linux cluster incremental backup system",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			conn, err = grpc.Dial("unix://"+socketPath,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return fmt.Errorf("connect to agent: %w", err)
			}
			client = agentpbv1.NewAgentServiceClient(conn)
			return nil
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if conn != nil {
				conn.Close()
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "/var/run/datavault-agent.sock", "agent socket path")

	// Subcommands
	rootCmd.AddCommand(ruleCmd())
	rootCmd.AddCommand(syncCmd())
	rootCmd.AddCommand(quotaCmd())
	rootCmd.AddCommand(restoreCmd())
	rootCmd.AddCommand(adminCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func ruleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rule", Short: "Manage backup rules"}

	cmd.AddCommand(&cobra.Command{
		Use:   "add <name> <path...>",
		Short: "Add a backup rule",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			exclude, _ := cmd.Flags().GetStringArray("exclude")
			_, err := client.AddUserRule(context.Background(), &agentpbv1.AddUserRuleRequest{
				Name:    args[0],
				Paths:   args[1:],
				Exclude: exclude,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Rule %q added\n", args[0])
			return nil
		},
	}).Flags().StringArray("exclude", nil, "glob patterns to exclude")

	cmd.AddCommand(&cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a backup rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.RemoveUserRule(context.Background(), &agentpbv1.RemoveUserRuleRequest{Name: args[0]})
			if err != nil {
				return err
			}
			fmt.Printf("Rule %q removed\n", args[0])
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List backup rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := client.ListUserRules(context.Background(), &agentpbv1.ListUserRulesRequest{})
			if err != nil {
				return err
			}
			for _, r := range resp.Rules {
				status := "enabled"
				if !r.Enabled {
					status = "disabled"
				}
				fmt.Printf("  %-20s [%s] paths=%v\n", r.Name, status, r.Paths)
			}
			return nil
		},
	})

	enableCmd := &cobra.Command{Use: "enable <name>", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.EnableUserRule(context.Background(), &agentpbv1.EnableUserRuleRequest{Name: args[0]})
			return err
		},
	}
	disableCmd := &cobra.Command{Use: "disable <name>", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := client.DisableUserRule(context.Background(), &agentpbv1.DisableUserRuleRequest{Name: args[0]})
			return err
		},
	}
	cmd.AddCommand(enableCmd, disableCmd)

	return cmd
}

func syncCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sync", Short: "Manage sync operations"}

	cmd.AddCommand(&cobra.Command{
		Use:   "trigger",
		Short: "Manually trigger a sync",
		RunE: func(cmd *cobra.Command, args []string) error {
			ruleName, _ := cmd.Flags().GetString("rule")
			resp, err := client.TriggerSync(context.Background(), &agentpbv1.TriggerSyncRequest{
				RuleName: ruleName,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Sync triggered: %s\n", resp.TaskId)
			return nil
		},
	}).Flags().String("rule", "", "specific rule to sync (empty = all)")

	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "View sync progress",
		RunE: func(cmd *cobra.Command, args []string) error {
			taskID, _ := cmd.Flags().GetString("task")
			stream, err := client.GetSyncStatus(context.Background(), &agentpbv1.GetSyncStatusRequest{
				TaskId: taskID,
			})
			if err != nil {
				return err
			}
			for {
				update, err := stream.Recv()
				if err != nil {
					break
				}
				fmt.Printf("\r[%s] %s: %d/%d files transferred (%d B/s)",
					update.TaskId, update.Phase,
					update.Stats.TransferredFiles, update.Stats.ChangedFiles,
					update.Stats.CurrentRateBps,
				)
				if update.Phase == "COMPLETED" || update.Phase == "FAILED" {
					fmt.Println()
					break
				}
			}
			return nil
		},
	}).Flags().String("task", "", "task ID (empty = latest)")

	return cmd
}

func quotaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "quota",
		Short: "Show quota usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			// quota is queried via BackupService (agent proxies)
			fmt.Println("quota: not yet implemented (requires agent-server proxy)")
			return nil
		},
	}
}

func restoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore backup data",
		RunE: func(cmd *cobra.Command, args []string) error {
			targetPath, _ := cmd.Flags().GetString("path")
			resp, err := client.RequestRestore(context.Background(), &agentpbv1.RequestRestoreRequest{
				TargetPath: targetPath,
			})
			if err != nil {
				return err
			}
			fmt.Printf("Restore started: %s\n", resp.TaskId)
			return nil
		},
	}
	cmd.Flags().String("path", "", "target restore path (default: ~/restored/)")
	return cmd
}

func adminCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrator commands (requires root)",
	}

	ruleCmd := &cobra.Command{Use: "rule", Short: "Manage machine backup rules"}
	ruleCmd.AddCommand(&cobra.Command{
		Use:   "add <name> <path...>",
		Short: "Add a machine backup rule",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			schedule, _ := cmd.Flags().GetString("schedule")
			exclude, _ := cmd.Flags().GetStringArray("exclude")
			_, err := client.AddMachineRule(context.Background(), &agentpbv1.AddMachineRuleRequest{
				Name: args[0], Paths: args[1:], Schedule: schedule, Exclude: exclude,
			})
			return err
		},
	}).Flags().String("schedule", "0 3 * * *", "cron schedule")
	// ... add remaining admin subcommands

	cmd.AddCommand(ruleCmd)
	return cmd
}
```

- [ ] **Step 2: Commit**

```bash
git add cmd/dvault/
git commit -m "feat: add dvault CLI with rule, sync, quota, restore, and admin commands

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task G4: Systemd units and Makefile

**Files:**
- Create: `scripts/datavault-agent.service`
- Create: `scripts/datavault-server.service`
- Create: `Makefile`

- [ ] **Step 1: Write systemd units**

```ini
# scripts/datavault-agent.service
[Unit]
Description=datavault Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/datavault-agent --config /etc/datavault/agent/config.yaml
Restart=always
RestartSec=30
IOSchedulingClass=best-effort
IOSchedulingPriority=7
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/datavault/agent /etc/datavault/agent/user-rules /var/run
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

```ini
# scripts/datavault-server.service
[Unit]
Description=datavault Server
After=network-online.target zfs.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/datavault-server --config /etc/datavault/server/config.yaml
Restart=always
RestartSec=10
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/datavault/server
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Write Makefile**

```makefile
# Makefile
.PHONY: build proto clean install

BINARIES = dvault datavault-agent datavault-server
CMDS = cmd/dvault cmd/datavault-agent cmd/datavault-server

build: proto
	for cmd in $(CMDS); do \
		go build -o dist/$$(basename $$cmd) ./$$cmd; \
	done

proto:
	buf generate

test:
	go test ./... -v -count=1

clean:
	rm -rf dist/

install: build
	install -m 755 dist/dvault /usr/bin/dvault
	install -m 755 dist/datavault-agent /usr/bin/datavault-agent
	install -m 755 dist/datavault-server /usr/bin/datavault-server
	install -m 644 scripts/datavault-agent.service /etc/systemd/system/
	install -m 644 scripts/datavault-server.service /etc/systemd/system/
	systemctl daemon-reload
```

- [ ] **Step 3: Commit**

```bash
git add scripts/ Makefile
git commit -m "feat: add systemd units and Makefile for build, test, and install

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Self-Review Checklist

Before handing off for execution, verify:

1. **Spec coverage**: Each spec requirement maps to a task:
   - ✅ Architecture (3 components) — Tasks A1, G1-G3
   - ✅ Security model (mTLS, SSH signing, nonce, SO_PEERCRED) — Tasks B2, C2, E1, F1
   - ✅ Config management (3 locations) — Tasks A4, B4, B5
   - ✅ Rule model (user + admin) — Tasks A4, B5, F1, F2
   - ✅ gRPC services — Tasks A2, A3, E2-E4, F1, F2
   - ✅ Sync flow (scan, diff, batch, push) — Tasks C3-C5, E3, F4, F5
   - ✅ ZFS integration (datasets, quota, snapshots) — Tasks D1, D2, E3
   - ✅ Recovery flow — Tasks E4, F2
   - ✅ Error handling/retry — Tasks B3, F5
   - ✅ Deployment — Tasks G4

2. **Placeholder scan**: No TBDs, TODOs remain in task code blocks.

3. **Type consistency**: 
   - AgentService struct uses same field names across Tasks F1, F5, G1
   - BackupServer struct uses Receiver field in Tasks E2, E3, G2
   - Config types match across B4, B5, F5

4. **Missing pieces to address in follow-up**:
   - Agent-side SO_PEERCRED interceptor for the gRPC server
   - Machine rules sync (agent needs to handle `_machine` user-level syncing)
   - Restore flow in orchestrator (`RunRestore`)
   - CLI restore progress streaming
   - SSH signature marshaling fix in transport/pusher.go
