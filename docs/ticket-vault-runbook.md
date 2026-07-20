# Ticket / Vault 运维手册（T02）

面向 **值班 / 安全运营 / 门户使用者**：如何为高危 SQL 开票、双人审批、在数据面注入票据、吊销，以及如何用 Vault 租约跑 SQL Portal。

> 这不是完整 BPM。外部工单系统（或 Admin API / data-ui）签发短时票据；网关只做 **subject + SQL 指纹 + 类型 + TTL + 次数** 校验。

相关代码：`gateway_core` 的 [`ticket.rs`](../data-proxy/gateway/core/src/ticket.rs)、[`vault.rs`](../data-proxy/gateway/core/src/vault.rs)；UI：`data-ui` 的 `/tickets`、`/vault`、`/portal`。

---

## 1. 概念对照

| 概念 | 是什么 | 不是什么 |
|------|--------|----------|
| **Ticket** | 绑定 **数据面 subject** + **SQL 指纹** 的短时许可 | 管理面 JWT / OIDC 角色 |
| **Vault lease** | 门户侧项目→后端身份绑定；**密码永不回传浏览器** | 直接连生产库的账号分发 |
| **Admin 身份** | 谁能 `POST /admin/tickets` | 默认 **不能** 冒充业务库用户（除非显式 vault/portal 绑定） |
| **高危规则** | `security.high_risk_rules` / 时间窗 `require_ticket` | 全量 DLP |

铁律（与开发规则一致）：

1. 门户 SQL **必须经 PEP**，禁止 UI 直连生产库拿结果。  
2. **管理面鉴权 ≠ 数据面 Subject**。  
3. Vault **永不在 Admin JSON 中返回后端密码**；revoke 后内存侧也不可再用于解析。

---

## 2. 何时需要 Ticket

配置侧常见触发：

| 来源 | 条件 | 常见 `ticket_type` |
|------|------|-------------------|
| `high_risk_rules` `kind=ddl` | CREATE/DROP/ALTER… | `ddl` |
| `kind=write_no_where` | UPDATE/DELETE 无顶层 WHERE | `high_risk` |
| `kind=action` / `table_write` | 匹配 action/table 列表 | 规则上的 `ticket_type` |
| `time_rules` `effect=require_ticket` | 窗口外（或内）写操作 | 规则上的 `ticket_type` |

客户端未带有效票时，网关返回协议错误，文案中含：

```text
prefix SQL with /*dn_ticket:<id>*/
```

---

## 3. 注释注入约定（数据面）

### 3.1 支持的写法

票据 id 必须出现在 **语句最前的块注释**（trim 后以 `/*` 开头）：

| 形式 | 示例 |
|------|------|
| 推荐 | `/*dn_ticket:tkt-…*/ CREATE TABLE …` |
| 别名 | `/* data_nexus_ticket: tkt-… */ …` |
| hint 形 | `/*+ dn_ticket=tkt-… */ …` |
| 空格 | `/* dn_ticket = tkt-… */ …` |

实现：`extract_ticket_id` / `strip_ticket_comment` / `sql_fingerprint`（指纹会 **剥掉** 票据注释再规范化）。

### 3.2 客户端注意

| 客户端 | 注意 |
|--------|------|
| **mysql CLI** | 必须 `--comments`，否则客户端会丢掉 `/*…*/`，网关看不到票 |
| **JDBC / 驱动** | 确认未剥注释；预编译路径仍走同一 SQL 文本提取（非 TCP passthrough prepared） |
| **psql** | 注释一般会保留；多语句脚本注意票只解析 **当前语句** 前缀 |
| **Portal** | 高危语句同样可在 SQL 文本前缀注入；portal 仍经 PEP |

### 3.3 指纹匹配规则（运维排错）

签发时 `sql` 与执行时 SQL（去票注释后）会：

1. 去掉票据注释  
2. 空白折叠为空格  
3. 转小写  
4. 去掉末尾 `;`

因此下列通常 **等价**：

```sql
/*dn_ticket:ID*/ CREATE TABLE IF NOT EXISTS t (id INT PRIMARY KEY)
/*dn_ticket:ID*/ create table if not exists t (id int primary key);
```

下列通常 **不等价**（会 subject/fingerprint 失败）：

- 改了表名 / 列 / 条件  
- subject 与签发时 `subject_id` 不一致（大小写不敏感比较）  
- 票类型与规则要求的 `ticket_type` 不一致  

默认：`max_uses=1`，`ttl_secs=600`。用尽或过期不可再 consume。

---

## 4. 开票（Admin API / UI）

### 4.1 权限

| 操作 | 权限（概念） | 路径 |
|------|----------------|------|
| 列表 | `runtime:read` | `GET /admin/tickets?limit=` |
| 签发 | `policy:write` | `POST /admin/tickets` |
| 审批 / 拒绝 / 吊销 / prune | `policy:write` | `POST …/approve|reject|revoke`，`POST /admin/tickets/prune` |

data-ui：`/tickets`（UI01）。

### 4.2 签发请求

```http
POST /admin/tickets
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "subject_id": "root",
  "sql": "CREATE TABLE IF NOT EXISTS smoke_ticket_t (id INT PRIMARY KEY)",
  "ticket_type": "ddl",
  "ttl_secs": 300,
  "max_uses": 1,
  "note": "change-window-2026-07-19",
  "issued_by": "alice",
  "dual_control": false
}
```

| 字段 | 说明 |
|------|------|
| `subject_id` | **数据面**身份（MySQL 用户名 / portal subject 等），不是 Admin 登录名（除非碰巧相同） |
| `sql` | 将执行的语句样例；用于指纹；会进 `sql_sample`（文件加密后仍属敏感） |
| `ticket_type` | 须满足高危规则要求（如 `ddl`） |
| `dual_control` | `true` → 状态 `pending`，需第二人批准后才是 `active` |
| `issued_by` | 双人场景强烈建议填写；自批校验依赖它 |

响应含 `id`、`status`、`sql_fingerprint`、`expires_at_unix_ms` 等。

### 4.3 单人票（默认）快速路径

```bash
# 1) 开票
curl -fsS -X POST "$ADMIN/admin/tickets" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"subject_id":"root","sql":"DROP TABLE IF EXISTS tmp_x","ticket_type":"ddl","ttl_secs":300,"max_uses":1}'

# 2) 客户端执行（mysql 务必 --comments）
mysql --comments -h … -P 9088 -u root -p \
  -e "/*dn_ticket:tkt-…*/ DROP TABLE IF EXISTS tmp_x;"
```

回归参考：`data-proxy/examples/smoke-security-ticket.sh`。

---

## 5. 双人审批（F18）

### 5.1 规则

1. `dual_control=true` 时签发 → `status=pending`。  
2. **pending 不可 consume**（数据面会拒绝）。  
3. `POST /admin/tickets/:id/approve` 的 `approved_by` **必须 ≠** `issued_by`（大小写不敏感）。  
4. 批准后 `status=active`，其后与单人票相同（指纹 / TTL / uses）。  
5. `reject` / `revoke`：未使用的 pending/active 可拒绝；**已 consume（uses>0）不能 reject**。  
6. `revoke` 在实现上是 `reject` 的运维别名。

### 5.2 推荐流程

```text
申请人 Alice                审批人 Bob                 执行人（可同 Alice）
    │ POST tickets              │                            │
    │ dual_control=true         │                            │
    │ issued_by=alice           │                            │
    ├──────────────────────────►│                            │
    │                           │ POST …/approve             │
    │                           │ approved_by=bob            │
    │◄──────────────────────────┤ status=active              │
    │ /*dn_ticket:id*/ SQL ─────────────────────────────────►│ 数据面 consume
```

### 5.3 示例

```bash
# 签发（pending）
curl -fsS -X POST "$ADMIN/admin/tickets" -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"subject_id":"root","sql":"CREATE TABLE t(id int)","ticket_type":"ddl",
       "issued_by":"alice","dual_control":true,"ttl_secs":300,"max_uses":1}'

# 自批必须失败
curl -sS -X POST "$ADMIN/admin/tickets/$ID/approve" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"approved_by":"alice"}'

# 第二人批准
curl -fsS -X POST "$ADMIN/admin/tickets/$ID/approve" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"approved_by":"bob"}'

# 拒绝
curl -fsS -X POST "$ADMIN/admin/tickets/$ID/reject" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"rejected_by":"bob","reason":"out of window"}'
```

回归：`data-proxy/examples/smoke-security-dual-control.sh`。

---

## 6. 吊销与清理

| 动作 | API | 效果 |
|------|-----|------|
| 吊销票 | `POST /admin/tickets/:id/revoke` body `{"rejected_by":"…","reason":"…"}` | 标 `rejected`，未使用票不可再 consume |
| 清理过期 | `POST /admin/tickets/prune` | 删除已过期条目（内存/文件后端） |
| 吊销租约 | `POST /admin/vault/leases/:id/revoke` | `revoked=true`，token 失效；密码侧不可再解析 |
| 续期租约 | `POST /admin/vault/leases/:id/renew` | 延长 TTL，**旋转** `access_token` |
| 清理租约 | `POST /admin/vault/leases/prune` | 去掉过期/已吊销等无效项 |

**建议**：误发票或变更取消 → 立即 revoke；周期任务 prune 过期项。多实例 `security.state.backend=file` 时，吊销依赖共享文件 + lock（全文件替换，**非 CRDT**，见 H05）。

---

## 7. Vault 与 SQL Portal（S6）

### 7.1 模型

```text
Admin / data-ui
  POST /admin/vault/leases { project, environment, ttl_secs }
       → lease_id + access_token + 元数据（无 password）
Portal
  POST /admin/portal/query { service, sql, lease_id?, subject_id?, max_rows, format }
       → 经 PEP → 后端；结果可 json / csv / ndjson
```

| 点 | 说明 |
|----|------|
| 密码 | 仅进程内存（及可选 **加密** vault 文件恢复）；Admin 列表/签发响应 **无 password 字段** |
| `lease_id` | 绑定审计 / 可选 subject；**不能**用来绕过表/列 ACL |
| `subject_id` | 数据面身份；与 ticket 的 `subject_id` 对齐时才能用同一张高危票 |
| 格式 | `json`/`csv` 物化；多行 `ndjson` 在 Streaming 后端为 `backend_window`（A09 诚实边界） |

### 7.2 运维操作

```bash
# 项目列表（常由 service 自动生成）
curl -fsS "$ADMIN/admin/projects" -H "Authorization: Bearer $TOKEN"

# 发租约
curl -fsS -X POST "$ADMIN/admin/vault/leases" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"project":"orders","environment":"dev","ttl_secs":600}'

# 门户查询（权限 runtime:read）
curl -fsS -X POST "$ADMIN/admin/portal/query" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"service":"orders","sql":"SELECT 1","subject_id":"portal-user","lease_id":"lease-…"}'

# 吊销
curl -fsS -X POST "$ADMIN/admin/vault/leases/$LEASE/revoke" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"reason":"session end"}'
```

UI：`/vault`、`/portal`。回归：`smoke-security-portal.sh`、`smoke-security-vault.sh`。

### 7.3 多实例（H05）摘要

| 配置 | 作用 |
|------|------|
| `security.state.backend=file` | ticket/vault JSON + advisory lock |
| `ticket_path` / `vault_path` | 共享路径（NFS/共享盘等） |
| `ticket_encrypt_key` / `vault_encrypt_key` | 64 hex；vault 无密钥则 **不落盘密码** |
| 进程内 secret | 活跃 lease 的 backend 密码在 RAM 中为普通 `String`；**revoke / prune / store Drop** 时 `zeroize` 擦除（**非** mlock / 安全堆）；`backend_identity` 返回副本，调用方勿记日志 |
| 文件一致性 | 全文件替换 + advisory lock，**last-writer-wins，非 CRDT** |

生产模板：[`data-proxy/examples/prod/`](../data-proxy/examples/prod/README.md)。

---

## 8. 排错速查

| 现象 | 排查 |
|------|------|
| 客户端报 ticket / require approval | 是否开票；类型是否匹配；是否 `/*dn_ticket:…*/` 前缀；mysql 是否 `--comments` |
| `subject mismatch` | 数据面登录用户 / portal `subject_id` 是否等于开票 `subject_id` |
| fingerprint 失败 | 执行 SQL 与开票 SQL 规范化后是否一致；勿改空白以外的语义 |
| `pending dual-control` | 是否已第二人 approve；是否自批 |
| `no remaining uses` | 默认一次性；需多次则开票时提高 `max_uses` 或重新开票 |
| 票已 reject 仍执行 | 应失败；确认未用错 id / 未打另一张 active 票 |
| Portal 403/deny | 与直连数据面同一套 rules；查 `/admin/audit/events?decision=deny` |
| lease 无效 | 过期、已 revoke、renew 后旧 token | 
| 多实例票看不见 | `state.backend=file` 路径是否共享；加密密钥是否一致 |

审计：高危拒绝 / require_ticket 走优先级队列（B07）；检索用 Admin Audit 页或 `GET /admin/audit/events`。

---

## 9. 配置片段（示例）

```toml
[security]
enabled = true
fail_closed = true

[[security.high_risk_rules]]
name = "require-ddl-ticket"
kind = "ddl"
ticket_type = "ddl"
message = "DDL requires approval ticket"

[[security.high_risk_rules]]
name = "require-write-no-where"
kind = "write_no_where"
ticket_type = "high_risk"
message = "UPDATE/DELETE without WHERE requires ticket"

# 可选多实例
[security.state]
backend = "file"
ticket_path = "/var/lib/data-nexus/tickets.json"
vault_path = "/var/lib/data-nexus/vault.json"
ticket_encrypt_key = "__DN_TICKET_ENCRYPT_KEY__"
vault_encrypt_key = "__DN_VAULT_ENCRYPT_KEY__"
```

---

## 10. 验证与边界（诚实）

| 验证 | 命令 / 入口 |
|------|-------------|
| 单人票 | `./examples/smoke-security-ticket.sh` |
| 双人 | `./examples/run-smoke-matrix.sh` 的 extended 组含 `smoke-security-dual-control.sh` |
| 门户 + vault | `smoke-security-portal.sh` / `smoke-security-vault.sh` |
| UI | data-ui `/tickets` `/vault` `/portal` |

**已知限制（勿当完整 GRC 宣传）**：

- 非外部 BPM / 通知 / SLA；无邮件审批流。  
- 指纹是规范化文本，不是语义等价证明。  
- write_no_where 为启发式（顶层 WHERE）。  
- 多实例文件态非 CRDT（last-writer-wins）。  
- 进程内 vault 密码：活跃期在 RAM；revoke/prune/Drop 时 zeroize（非 mlock）；`backend_identity` 返回副本。  
- Admin JWT 不会自动成为数据面 subject。

---

## 11. 相关链接

| 文档 | 用途 |
|------|------|
| [`data-security-roadmap.md`](data-security-roadmap.md) | S5/S6 产品定义 |
| [`data-nexus-tech-architecture-2026.md`](data-nexus-tech-architecture-2026.md) | 技术主文档 |
| [`data-ui/docs/oidc-production.md`](../data-ui/docs/oidc-production.md) | 管理面 SSO（H04） |
| [`data-proxy/examples/prod/README.md`](../data-proxy/examples/prod/README.md) | 生产配置包 |
| 看板 `todo.md` T02 | 完成勾选 |

修订：T02 运维叙事收口；行为以代码与 smoke 为准。
