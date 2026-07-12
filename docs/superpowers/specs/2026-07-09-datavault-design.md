# dvault — 设计规格书

> 日期: 2026-07-09
> 状态: 已评审

---

## 1. 项目概述

dvault 是一个面向 Linux 集群的增量文件备份系统，用于灾难恢复场景。
分为三个组件：`dvault`（命令行工具）、`datavault-agent`（Client 端守护进程）、`datavault-server`（备份存储守护进程）。
不支持版本管理——目标是保证硬盘发生灾难性故障时能够恢复数据。

### 核心约束

| 维度 | 决策 |
|------|------|
| 拓扑 | 多 Client → 多 Server（以多对一为主），Client 指定 Server 地址 |
| 变更检测 | 定时轮询扫描（凌晨窗口），低 IO 影响 |
| 传输策略 | 分段打包（1000 文件/batch），细粒度进度 |
| 规则配置 | 配置文件 + CLI 命令 |
| 用户认证 | Linux 系统用户身份 + SSH key 签名验证 |
| 通信协议 | gRPC（AgentService Unix socket + BackupService TCP/mTLS） |
| ZFS 集成 | 完全 ZFS 原生（每用户 dataset，ZFS quota，独立快照） |
| 进度展示 | 细粒度实时终端面板 |
| 实现语言 | Go |
| 容错 | 自适应重试 + 指数退避 + hook 脚本通知 |
| 恢复 | 基础全量恢复 |

---

## 2. 架构总览

### 三层结构

```
dvault        — 命令行交互工具
    ↓ gRPC (Unix socket, SO_PEERCRED)
datavault-agent      — 每台 Client 机器的后台守护进程
    ↓ gRPC (TCP, mTLS + SSH Key 签名)
datavault-server     — 备份存储 Server，管理 ZFS
```

### 组件职责

| 组件 | 职责 | 对外接口 |
|------|------|---------|
| dvault | 用户交互：规则管理、手动触发、进度查看、恢复请求 | 仅与本地 Agent 通过 Unix socket 通信 |
| datavault-agent | 定时调度、文件扫描、增量计算、批量同步、进度上报 | AgentService（给 CLI）+ BackupService 客户端（给 Server） |
| datavault-server | 数据接收落盘、ZFS dataset/quota/快照管理、恢复服务 | BackupService（TCP/mTLS） |

---

## 3. 安全模型

### 核心原则：Server 不信任 Agent

Agent 在 Client 机器上可能有 root 权限，但 Server 不因此开放全部能力。

### 双层认证

```
第一层 — 机器身份（mTLS）：
  Agent 持有 mTLS 证书，CN = hostname
  Server 维护 allowed_hosts 白名单
  → 证明连接来自已注册的机器

第二层 — 用户身份（CLI 端 SSH Key 签名）：
  CLI 以用户身份运行，通过 ssh-agent 对请求签名
  sig = Sign(ssh_agent, nonce || method_name || sha256(payload))
  Agent 原样转发签名到 Server
  Server 用 authorized_keys 中该用户的公钥验证
  → 证明操作由用户本人发起
```

### 签名流程

```
CLI → Agent (Unix socket):
  1. 请求 challenge nonce
  2. 用 ssh-agent 生成签名（私钥从未离开 ssh-agent 内存）
  3. 发送 {user, nonce, method, payload, signature}

Agent 处理:
  1. SO_PEERCRED 获取对端 UID → 确定 user
  2. 忽略 CLI 传来的 user 字段，用 SO_PEERCRED 覆盖
  3. 原样转发签名请求到 Server

Server 验证:
  1. mTLS: 证书 CN 是否在 allowed_hosts 中
  2. Nonce: 未过期、未使用过
  3. 签名: authorized_keys[hostname][user] 公钥验证
  4. 用户-主机绑定: 该 user 是否被授权在此 hostname 上操作
  5. 写入 pool/hostname/user/
```

### 权限边界

| 操作 | Agent 能做到 | Agent 不能做到 |
|------|:---:|------|
| 推送备份数据 | ✅ | 不可删除已有数据 |
| 覆盖同一路径 | ✅ | 旧版本在 snapshot 中不可变 |
| 删除/修改 snapshot | ❌ | 无对应 RPC，仅 Server 管理员本地操作 |
| 修改其他用户数据 | ❌ | Dataset 隔离 + 签名验证 |
| ZFS 管理 | ❌ | 全部禁止 |
| 发起恢复 | ✅（仅限自己的数据） | 目标路径限制在 $HOME 内 |

### Nonce 设计

- 生成: `random(32)` 来自 CSPRNG
- 过期: 5 分钟
- 签名绑定: `nonce || method_name || sha256(payload)`
- Server 端标记为 used 在签名验证成功之后（防止 DoS）
- TTL 过后 GC 清理

### 恢复功能安全

Agent 端恢复路径校验（不可绕过）:
1. `filepath.Clean()` 规范化
2. 验证前缀在请求用户的 $HOME 内
3. `lstat` 检查目标不是符号链接
4. 目标目录属主 = CLI 对端 UID
5. 先写入临时目录，全部完成 + 校验通过后 `rename()` 原子替换

### ZFS 命令安全

- 所有 `zfs`/`zpool` 命令使用 `exec.Command` 分参数执行
- 禁止通过 `sh -c` 执行任何 ZFS 命令
- 所有数据集名称执行严格正则验证

### gRPC 安全加固

- `MaxConcurrentStreams`: 100
- `MaxRecvMsgSize`: 16MB
- Keepalive: `MinTime=30s`, `PermitWithoutStream=false`
- 所有 stream handler 带 `context.WithTimeout`（10 分钟上限）
- 禁止 gRPC reflection 在生产环境
- Go 1.21+ 确保修复 HTTP/2 Rapid Reset

---

## 4. 配置管理与三地分离

### 配置分布

| 配置项 | 在哪 | 谁维护 |
|--------|------|:---:|
| 用户备份路径 + 排除规则 | Agent: `user-rules/<user>.yaml` | 用户（CLI） |
| 系统目录备份规则 + 调度时间 + Server 连接列表 | Agent: `config.yaml` | 管理员 |
| 全局强制规则 + 用户 quota + 默认调度 + 允许主机 | Server: `/etc/datavault/server/config.yaml` | 管理员 |
| ZFS quota 强制执行 | ZFS dataset 自身 | ZFS |

### Server 配置

```yaml
# /etc/datavault/server/config.yaml
server:
  cert_file: "/etc/datavault/server/cert.pem"
  key_file: "/etc/datavault/server/key.pem"
  ca_file: "/etc/datavault/server/ca.pem"
  listen: "0.0.0.0:8443"
  backup_pool: "tank/backups"

allowed_hosts:
  - cn: "web-01.example.com"
  - cn: "web-02.example.com"

global_rules:
  - name: "ssh-host-keys"
    paths: ["/etc/ssh"]
    exclude: ["*.pub"]
  - name: "system-auth"
    paths: ["/etc/pam.d", "/etc/security"]

user_policy:
  default_schedule: "30 3 * * *"
  default_quota_gb: 20
  per_user_overrides:
    alice:
      quota_gb: 100

snapshot_policy:
  min_snapshots: 2
  max_snapshots: 7
  min_free_gb: 1000
```

### Agent 配置

```yaml
# /etc/datavault/agent/config.yaml
agent:
  cert_file: "/etc/datavault/agent/cert.pem"
  key_file: "/etc/datavault/agent/key.pem"
  ca_file: "/etc/datavault/agent/ca.pem"

servers:
  - address: "backup01.example.com:8443"
  - address: "backup02.example.com:8443"

machine_rules:
  - name: "app-config"
    paths: ["/opt/app/config", "/opt/app/data"]
    schedule: "0 3 * * *"
    exclude: ["*.log"]

retry:
  initial_interval: 60s
  max_interval: 1800s
  multiplier: 2.0
  jitter: 0.1
  max_elapsed_time: 14400s

hooks:
  on_task_failed: "/usr/local/bin/datavault-alert.sh"
  on_quota_warning: "/usr/local/bin/datavault-quota-warn.sh"
```

### 规则合并与认证

Agent 执行同步时，不同来源的规则使用不同的认证和 Dataset：

| 规则来源 | 合并方式 | 认证 | 写入 Dataset |
|---------|---------|------|-------------|
| Server.global_rules | 合并到每个用户的备份中 | 用户 SSH Key 签名 | `pool/hostname/username/` |
| 用户个人规则 | 按用户独立执行 | 用户 SSH Key 签名 | `pool/hostname/username/` |
| Agent.machine_rules | 独立执行 | mTLS 机器身份 | `pool/hostname/_machine/` |

机器规则不绑用户——由管理员在 Agent 端配置，mTLS 已证明机器身份，Server 允许已验证 hostname 向 `_machine/` dataset 写入。

```
用户 alice 的最终备份规则 =
    Server.global_rules
  + 用户 alice 的个人规则（来自 user-rules/alice.yaml）
  + Server.user_policy[alice]（调度时间和 quota）
```

### 多 Server 冗余

Agent 独立向每个 Server 发起连接、独立传输、独立报告状态。同一数据并行发往所有已配置 Server。

---

## 5. 备份规则模型

### 用户可操作

- `dvault rule add/remove/list/enable/disable` — 管理个人备份路径
- `dvault sync trigger/status` — 手动触发和进度查看
- `dvault quota` — 查看 quota 用量
- `dvault restore [--path]` — 请求恢复

### 用户不可操作

- 修改调度时间
- 修改 quota
- 查看/修改他人规则
- 查看/修改管理员规则
- 修改 Server 连接配置

### 管理员命令

```
dvault admin rule add/remove/list    ← 系统目录备份规则
dvault admin server add/remove/list  ← 目标 Server 管理
```

### 规则属性

| 属性 | 必需 | 说明 |
|------|:---:|------|
| name | ✅ | 唯一标识 |
| paths | ✅ | 备份路径列表 |
| exclude | 否 | glob 排除规则 |
| schedule | ✅（管理员设置） | cron 表达式 |
| enabled | 否（默认 true） | 暂停/启用 |

### 排除规则

- Glob 模式匹配文件的相对路径（相对于备份根路径），而非仅匹配文件名
- 使用标准 Unix shell glob（`*` 单层, `**` 任意层）
- 匹配路径中任意位置的模式（如 `**/node_modules/` 匹配任意深度）
- 示例：
  - `*.tmp` — 匹配根路径下以 .tmp 结尾的文件
  - `**/*.mp4` — 匹配任意深度下的 .mp4 文件
  - `**/node_modules/**` — 匹配任意深度下的 node_modules 目录及内容
  - `target/` — 匹配根路径下的 target 目录

---

## 6. gRPC 服务定义

### AgentService（CLI ↔ Agent，Unix socket）

```protobuf
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
```

### BackupService（Agent ↔ Server，TCP + mTLS）

```protobuf
service BackupService {
  rpc GetChallenge(GetChallengeRequest) returns (Challenge);
  rpc GetGlobalConfig(GetGlobalConfigRequest) returns (GlobalConfig);
  rpc PushBackup(stream BackupBatch) returns (stream BatchAck);
  rpc GetQuotaUsage(GetQuotaUsageRequest) returns (QuotaUsage);
  rpc PullRestore(PullRestoreRequest) returns (stream RestoreBatch);
}
```

### 同步流程

```
1. Agent 连接到每个 Server
2. GetChallenge → nonce
3. Agent 扫描文件（基于 mtime + size + sha256 增量比对）
4. 差异文件分批打包（1000 文件/batch），每批:
   Agent → Server: PushBackup(stream) {batch_id, user, files, signature}
   Server → Agent: BatchAck {batch_id, status}
5. 全部完成后 Server 自动打 ZFS snapshot
```

### 增量检测

Agent 本地 SQLite 维护已同步文件状态快照：

```sql
CREATE TABLE file_snapshots (
  server_id  TEXT,
  username   TEXT,
  file_path  TEXT,
  mtime_ns   INTEGER,
  size_bytes INTEGER,
  sha256     BLOB,
  synced_at  INTEGER,
  PRIMARY KEY (server_id, username, file_path)
);
```

比对逻辑：
- 新文件（不在表中）→ 加入差异列表
- mtime 或 size 变化 → 计算 sha256 对比 → 不同则加入
- 文件已不存在 → 发送删除指令
- 完全一致 → 跳过

---

## 7. Agent 内部模块

| 模块 | 职责 | 关键点 |
|------|------|--------|
| gRPC 接口层 | 对接 CLI 的 AgentService | SO_PEERCRED 验证 UID |
| 调度引擎 | cron 定时器，到时间触发任务 | 限制凌晨 0-6 点 |
| Server 连接池 | 维护到各 Server 的 gRPC 连接 | TLS 会话复用，健康检查 |
| 任务编排器 | 合规则 → 扫描 → diff → 打包 → 推送 → 更新快照 | 每个 (user, server) 独立追踪 |
| 扫描引擎 | 游走目录树，产文件元信息列表 | ionice + 读取间歇限速 |
| 传输引擎 | 分批打包，gRPC streaming 推送 | 单批失败只重传该批 |
| 持久化层 | SQLite（快照表 + 任务历史）+ YAML 配置 | WAL 模式 |

### IO 影响控制

- `ionice -c2 -n7`（best-effort，最低优先级）
- 大目录分段处理（>10000 文件时分段）
- 网络带宽限制（可配置，默认 100MB/s）
- 单 batch 内存上限 256MB

---

## 8. Server 内部模块

| 模块 | 职责 | 关键点 |
|------|------|--------|
| gRPC 接口层 | BackupService | 全局 auth interceptor |
| 认证中间件 | mTLS + nonce + SSH 签名 + user-host 绑定 | 白名单豁免仅 GetChallenge |
| 配置管理器 | 加载/重载 config.yaml | SIGHUP 触发 |
| 接收引擎 | PushBackup stream → 逐 batch 落盘 → 确认 | 路径遍历防护 |
| ZFS 管理器 | 封装 `zfs` 命令，dataset/quota/snapshot/rollback | exec.Command 分参数，禁止 shell |
| 持久化层 | SQLite（nonce 表 + quota 缓存） | nonce 带 TTL 自动 GC |

### ZFS Dataset 组织

```
tank/backups/
  ├── web-01/
  │   ├── alice/
  │   ├── bob/
  │   └── _machine/    ← machine_rules 数据
  └── db-01/
      └── charlie/
```

### Snapshot 命名与保留

- 命名: `sync-YYYYMMDD-HHMMSS`
- 创建时机: 每次 PushBackup 全部完成之后
- 保留策略: `min_snapshots=2`, `max_snapshots=7`, `min_free_gb=1000`
- 清理: 从最旧开始删除，min_snapshots 为硬底线
- 策略目的: 保证至少保留 2 个成功快照作为安全回退窗口

---

## 9. 恢复流程

```
CLI → Agent: dvault restore [--path <target>]
Agent 校验:
  1. filepath.Clean() + $HOME 前缀检查
  2. lstat 非符号链接
  3. 目标属主 = CLI 对端 UID
  4. 先在临时目录写入，完成后 rename() 原子替换
Agent → Server: PullRestore {user, nonce, signature}
Server → Agent: RestoreBatch stream
Agent: 写入文件，进度回报给 CLI
```

恢复仅支持最新数据的全量恢复。目标路径默认 `~/restored/`，必须在请求用户的 `$HOME` 内。

---

## 10. 错误处理与重试

### 错误分类与策略

| 错误类型 | 策略 |
|---------|------|
| 瞬时故障（网络超时、连接 reset） | 指数退避重试 (60s→120s→...→1800s)，总重试 4h，超时后执行 failure_hook |
| 资源故障（磁盘满、quota 超限） | 固定间隔重试 3 次，放弃后通知 |
| 数据错误（权限不足、checksum 不匹配） | 跳过该文件，记录日志，不影响同批 |
| 认证错误（证书过期、签名失败） | 不重试，立即停止，日志告警 |
| 不可恢复（配置解析失败、SQLite 损坏） | 不重试，Agent 退出 |

### 重试参数

```yaml
retry:
  initial_interval: 60s
  max_interval: 1800s
  multiplier: 2.0
  jitter: 0.1
  max_elapsed_time: 14400s
```

### 失败通知

Hook 脚本接收环境变量：`AUTOBACK_EVENT`, `AUTOBACK_TASK_ID`, `AUTOBACK_USER`, `AUTOBACK_SERVER`, `AUTOBACK_ERROR`, `AUTOBACK_ELAPSED`。

### 信号处理

- SIGHUP: 重载配置
- SIGTERM/SIGINT: 完成当前 batch 后优雅退出

---

## 11. 部署与运维

### 文件布局

```
Client 机器:
  /usr/bin/dvault                          ← CLI
  /usr/bin/datavault-agent                    ← Agent 守护进程
  /etc/datavault/agent/{config.yaml,cert.pem,key.pem}
  /etc/datavault/agent/user-rules/            ← 用户规则（每用户一个文件）
  /var/lib/datavault/agent/state.db           ← SQLite
  /etc/systemd/system/datavault-agent.service

Server 机器:
  /usr/bin/datavault-server                   ← Server 守护进程
  /etc/datavault/server/{config.yaml,cert.pem,key.pem}
  /etc/datavault/server/authorized_keys/      ← 用户公钥（按 hostname 分组）
  /etc/datavault/server/ca/                   ← CA 证书和私钥
  /var/lib/datavault/server/state.db          ← SQLite
  /etc/systemd/system/datavault-server.service
```

### Systemd 安全加固

```
Agent:  PrivateTmp=yes, ProtectSystem=strict, ProtectHome=read-only,
        NoNewPrivileges=yes, IOSchedulingClass=best-effort, IOSchedulingPriority=7

Server: PrivateTmp=yes, ProtectSystem=strict, NoNewPrivileges=yes
```

### 证书管理

```
初始化:
  datavault-server init-ca                  → 自建 CA
  datavault-server init-cert                → Server 自签证书
  datavault-server sign-agent --hostname X  → 签发 Agent 证书

分发:
  管理员通过安全通道（scp）将证书分发到 Client 机器
  dvault admin cert install              → Agent 端安装

续期:
  证书有效期 90 天，过期前 14 天 Agent 日志警告
  Server 重新签发 → scp 分发 → Agent 自动加载
```

### 配置重载

```
systemctl reload datavault-agent   → SIGHUP → 重载配置，不中断运行中任务
systemctl reload datavault-server  → SIGHUP → 重载配置，不中断现有连接
```

### 监控

Agent: 上次同步时间、文件数/字节数、失败次数、下次调度时间
Server: 每 dataset 用量/quota、快照数量、磁盘剩余、活跃连接数

---

## 12. 设计决策记录

| 决策 | 选择 | 原因 |
|------|------|------|
| 调度方式 | 定时轮询 | 面向凌晨低频窗口，不需要实时 |
| 传输策略 | 分段打包 1000 文件/batch | 兼顾效率和进度可见性 |
| ZFS 集成深度 | 完全原生 | 独立 dataset 隔离 + quota 精准 + 独立快照 |
| 签名位置 | CLI 端（ssh-agent） | Root Agent 无法窃取用户签名 |
| 机器身份 | mTLS CN（不用 MAC） | MAC 可伪造，CN 绑定到管理员的信任决策 |
| Server 间关系 | 无状态独立节点 | 冗余由 Agent 多 Server 连接实现 |
| Agent 对 Server | 仅追加 | 无删除 RPC，历史数据在 snapshot 中不可变 |
| 恢复路径 | 仅限用户 $HOME | 防跨用户写入和路径遍历 |
