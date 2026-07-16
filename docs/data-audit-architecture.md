# Data Nexus：数据审计与安全改写技术架构

**状态**：技术规划（专项）  
**关联**：`docs/data-nexus-tech-architecture-2026.md`（**技术主文档，冲突时以之为准**）、`docs/data-security-roadmap.md`（产品分期）、`docs/data-nexus-protocol-gateway-plan.md`（协议底座）  
**目标场景**：按安全规则对 **表 / 字段 / 行** 做筛选、去除、打码、替换，并完成可追溯审计；同时满足 **高并发、低延迟、大结果集、低内存**。

---

## 1. 问题定义

### 1.1 功能需求

| 维度 | 能力 |
|------|------|
| **表** | 禁止访问 / 仅允许列表 / 操作类型限制（SELECT/DML/DDL） |
| **字段（列）** | 剔除列、禁止投影、动态脱敏（mask/partial/hash/replace/nullify） |
| **行** | 谓词注入（租户/组织）、结果过滤、行数上限 |
| **审计** | 谁、何时、何库何表、何语句、决策、义务、行数/字节、可选样本 |
| **通道** | 协议代理 / 导出 / 门户 统一策略语义 |

### 1.2 非功能需求（约束）

| 约束 | 含义 | 架构含义 |
|------|------|----------|
| **高并发** | 万级连接、高 QPS | 主路径无阻塞 IO；无全局大锁；每连接状态隔离 |
| **快速查询** | P99 延迟接近直连 | 无义务时走快路径；有义务时流式、少拷贝 |
| **大数据查询** | 百万～亿级行、宽表 | **禁止全结果进内存**；边读边处理边写 |
| **低内存** | 单实例可控 RSS | 峰值 O(连接数 × 行窗口)，非 O(结果集) |
| **正确性** | 协议兼容、策略可解释 | 解析失败策略可配；审计不拖垮主路径 |

### 1.3 当前实现与目标差距（一句话）

当前：`全量 Backend → 全量 GatewayValue → 全量协议包 → 写出`。  
目标：`流式/分窗 + 策略义务就地执行 + 异步审计`；无义务时 **同协议透传**。

---

## 2. 总体架构

### 2.1 逻辑分层

```text
┌─────────────────────────────────────────────────────────────┐
│ Control Plane（控制面，可独立扩缩）                           │
│  · 策略配置 / 资产标签 / 审批工单 / 审计检索 API / Admin UI    │
└───────────────────────────▲─────────────────────────────────┘
                            │ 下发策略 / 拉配置 / 查审计
┌───────────────────────────┴─────────────────────────────────┐
│ Data Plane · Data Nexus Gateway（数据面，多实例）              │
│                                                             │
│  Frontend (MySQL/PG wire)                                   │
│       │                                                     │
│       ▼                                                     │
│  ┌─ Session / Subject ──────────────────────────────────┐   │
│  │  身份、client_addr、channel、事务状态                   │   │
│  └───────────────────────┬──────────────────────────────┘   │
│                          ▼                                  │
│  ┌─ SQL Analyze ────────────────────────────────────────┐   │
│  │  AST / 对象抽取 → ObjectAccess[] + risk_hints          │   │
│  └───────────────────────┬──────────────────────────────┘   │
│                          ▼                                  │
│  ┌─ PDP（进程内缓存 + 可选远程）──────────────────────────┐   │
│  │  Allow | Deny | Allow+Obligations | RequireTicket     │   │
│  └───────────────────────┬──────────────────────────────┘   │
│                          ▼                                  │
│  ┌─ Execution Path 选择器 ───────────────────────────────┐   │
│  │  Fast: 同协议透传 / 零义务流式                          │   │
│  │  Secure: 解析路径 + 流式改写（mask/filter）             │   │
│  └───────────────────────┬──────────────────────────────┘   │
│                          ▼                                  │
│  Backend Connector ──流式行/包──► Obligation Engine          │
│                          │              │                   │
│                          │              ▼                   │
│                          │         Frontend encode(流式)    │
│                          ▼                                  │
│                   Audit Emitter (非阻塞)                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
              Audit Pipeline（异步、有界、批量）
              → 本地/OTLP/对象存储（冷数据可 Parquet）
```

### 2.2 两条执行路径（性能关键）

| 路径 | 条件 | 行为 | 内存 |
|------|------|------|------|
| **Fast Path** | 同协议 + 无脱敏/行过滤义务 + 策略允许 | 包级或行级透传/轻量转发 | O(包窗口) |
| **Secure Path** | 跨协议 / 需 mask / 行过滤 / 需改 SQL | 解析 → 可能 Rewrite SQL → 流式读 → 逐行义务 → 编码写出 | O(行窗口) |

**原则**：默认尽量走 Fast Path；只有策略要求时才付 Secure Path 成本。

### 2.3 与现有模块映射

| 逻辑组件 | 现有落点 | 演进 |
|----------|----------|------|
| Frontend / Backend | `runtime/gateway/src/frontend|backend` | 增加流式 API |
| 命令编排 | `core_engine.rs` | 插入 Analyze → PDP → Path 选择 → Obligations |
| 方言/AST | `dialect.rs`、`mysql_parser`、`sqlparser` | 对象抽取 `ObjectAccess` |
| 插件 | `plugin` | 治理保留；安全 PDP 独立 |
| 跨协议 | `translation` | 与 security 顺序可配 |
| Admin | `http` + AdminAuth | 管策略配置权限，不混数据面 Subject |
| 审计 | `data_nexus::audit` 日志 | 异步管道 + 分级事件 |

---

## 3. 数据处理流水线（表 / 字段 / 行）

### 3.1 阶段划分

```text
① 连接建立     → Subject 绑定
② SQL 到达     → 解析 / 对象抽取 / 指纹
③ 策略决策     → PDP（可缓存）
④ SQL 义务     → 行级：谓词注入；列级：禁止列 → 改写投影或拒绝
⑤ 后端执行     → 流式拉取
⑥ 结果义务     → 行过滤（若未注入）/ 列去除 / 打码 / 替换 / 水印
⑦ 协议编码     → 流式写客户端
⑧ 审计收尾     → row_count、bytes、decision 补全事件
```

### 3.2 规则动作与执行层

| 规则意图 | 推荐执行层 | 技术要点 |
|----------|------------|----------|
| 表禁止访问 | **Pre-execute Deny** | 对象抽取后立刻拒绝，不打后端 |
| 列禁止 SELECT | **SQL 改写** 去掉列，或 Deny | 改写需 AST；失败则 Deny |
| 列脱敏 | **结果集流式 mask** | 按列下标改 `GatewayValue`，不缓冲全表 |
| 行过滤（租户） | **优先 SQL 谓词注入** | `AND tenant_id = $sid`；次选结果过滤（更耗） |
| 行数上限 | **流式计数截断** | 达上限发协议 EOF/错误策略可配 |
| 替换/打码算法 | **列义务函数表** | mask/partial/hash/replace 可插拔、无分配优先 |
| 整句高危 | **RequireTicket** | 不执行直至票据 |

### 3.3 义务（Obligation）模型

```text
Obligations {
  rewrite_sql: Option<String>,
  drop_columns: [ordinal or name],
  mask_columns: [{ ordinal, algorithm, params }],
  row_filter: Option<Expr>,      // 尽量下推为 rewrite_sql
  max_rows: Option<u64>,
  watermark: Option<WatermarkSpec>,
  audit_level: L0|L1|L2
}
```

PEP 只执行义务，不解释业务政策语言（政策在 PDP/配置编译期展开）。

---

## 4. 性能架构：高并发 / 大数据 / 低内存

### 4.1 内存模型

| 对象 | 目标占用 |
|------|----------|
| 每连接 | 固定状态 + 当前窗口（1～N 行或 1～M 协议包） |
| 全局 | 策略缓存、连接池、审计队列（有界） |
| **禁止** | `Vec<全部行>` + `Vec<全部协议包>` 同时常驻 |

**行窗口**：默认 1 行流水线；吞吐不足时用 **小 batch**（如 32～256 行）换 CPU 缓存友好，仍远小于全量。

### 4.2 并发模型

```text
每个客户端连接 = 1 个异步任务（现有模式）
  · 无跨连接共享可变结果缓冲
  · PDP 只读策略 + 版本号；热更新 copy-on-write / ArcSwap
  · 审计 try_send 到有界 channel；worker 池批量写
  · 连接池（后端）与客户端并发解耦
```

**避免**：

- 全局 `Mutex` 保护大 HashMap 策略（用分片或 lock-free 读）
- 审计同步 `fsync` / 同步 HTTP
- 在热路径 `clone` 整个 `ResultSet`

### 4.3 大数据查询策略

| 手段 | 作用 |
|------|------|
| 流式读后端 | 不积压 |
| 流式写前端 | 首字节延迟低 |
| max_rows / max_result_bytes | 硬限制，防拖垮 |
| 超时 | 语句级 / 空闲级 |
| 背压 | 客户端慢 → 停止读后端（async 自然背压） |
| 拒绝「必须全量物化」的义务组合 | 如「全结果水印排序」等放到导出通道 |

### 4.4 快速查询策略

| 场景 | 路径 |
|------|------|
| 同协议 + Allow 无义务 | **包透传**（不进 `GatewayValue`） |
| 同协议 + 仅审计 L0 | 透传 + 异步记指纹/表名 |
| 需列脱敏 | Secure 流式：只解析需要的列类型信息 |
| 跨协议 | 必须 IR，但 **逐行** IR，不整表 IR |

### 4.5 拷贝预算（目标）

| 路径 | 目标拷贝次数（单元格有效载荷） |
|------|--------------------------------|
| Fast 透传 | **0～1**（socket→socket，内核可再拷） |
| Secure 流式 mask | **1～2**（wire→值改写→wire 包） |
| 当前全量 IR | **2～3+**（需淘汰） |

---

## 5. 需要的技术清单（分类）

### 5.1 必须有（与是否「新潮」无关）

| 技术点 | 用途 |
|--------|------|
| **可靠 SQL 解析 / 对象抽取** | 表列行策略前提（MySQL AST + PG sqlparser，统一 `ObjectAccess`） |
| **流式结果 API** | 替代 `Vec<Vec<GatewayValue>>` 全量 |
| **同协议包透传** | 高并发基线 |
| **PDP + 义务模型** | 规则决策与执行分离 |
| **列级 mask 函数** | 打码/替换/去除 |
| **异步有界审计管道** | 高并发下审计不拖垮 QPS |
| **策略缓存与版本** | 热更新、低锁 |
| **分级审计** | 控制审计数据量 |

### 5.2 强烈推荐

| 技术点 | 用途 |
|--------|------|
| `bytes::Bytes` / 缓冲池 | 少分配 |
| 协议包直接转发缓冲 | 透传零解析 |
| 批量审计编码（Protobuf/MessagePack） | 降 CPU |
| OTLP logs / 现有 OTel | 外发与关联 trace |
| 配置化 fail_closed / max_rows | 生产安全阀 |

### 5.3 可选 / 后期

| 技术 | 何时用 |
|------|--------|
| **Apache Parquet** | 审计/导出 **冷归档**、合规离线分析（按日分区） |
| **Apache Arrow** | 网关内要做 **列式批量计算**、对接分析引擎时；**不作 wire IR** |
| Kafka / Pulsar | 审计事件量极大、多消费者时 |
| DataFusion / Polars | 审计湖上交互分析，非代理热路径 |
| 向量化 mask（SIMD） | profiling 证明脱敏 CPU 打满后再做 |
| 行存压缩（zstd）审计文件 | 本地高吞吐落盘 |

### 5.4 不建议作为热路径基础

- 全量进 Arrow 再转回 MySQL/PG 协议  
- 同步写 Parquet 在查询路径上  
- 用正则插件承载全部表列行策略  

---

## 6. 核心子系统设计

### 6.1 SQL Analyze（对象抽取）

```text
Input:  sql + dialect
Output: StatementKind, ObjectAccess[], fingerprint, parse_status
```

- **S1**：best-effort 表名 + 语句类型（可启发式 + AST 混合）  
- **S2**：AST visitor 列级  
- 缓存：`sql_fingerprint → AnalyzeResult`（LRU，注意绑定 dialect）

### 6.2 PDP

```text
Input:  Subject + AnalyzeResult + Service + Channel
Output: Decision + Obligations
```

- 进程内：规则编译为匹配器（glob / 前缀树 / 位图角色）  
- 远程：gRPC `Check(PolicyRequest) → PolicyResponse`，带超时与本地否定缓存  
- **热路径缓存键**：`(subject_hash, service, fingerprint, policy_version)` → Decision  

### 6.3 Obligation Engine（流式）

```text
for await row in backend_rows:
    if row_filter: maybe skip
    apply drop_columns / mask_columns
    if watermark: stamp
    encode_and_write(row)
    count++
    if max_rows reached: break
emit_audit_final(count)
```

接口形态建议：

```rust
// 概念 API，非最终代码
trait RowStream {
    async fn next_row(&mut self) -> Option<Result<RowCow>>;
}
trait ResultSink {
    async fn write_row(&mut self, row: &RowView) -> Result<()>;
    async fn finish(&mut self) -> Result<()>;
}
```

`RowCow`：能借用 backend buffer 则借，需改写时再 copy-on-write 单行。

### 6.4 审计管道

```text
AuditEvent (L0 默认小)
  → try_send (有界)
  → Worker: batch → encode → sink

满队列策略（可配）:
  - drop_metadata_only 事件 + metric
  - 或 block（低优先）
  - 高危 Deny 可同步记一条最小事件（仍避免写盘 fsync）
```

**分级**：

| 级别 | 内容 | 默认 |
|------|------|------|
| L0 | 元数据 + fingerprint + objects + counts | 全开 |
| L1 | + SQL 截断全文 | 可配 |
| L2 | + 样本行（已脱敏） | 仅命中规则 |
| L3 | 全结果 | 几乎禁用 |

### 6.5 算法插件（脱敏/替换）

```text
MaskAlgorithm: fn(&ValueRef, &Params, &mut WriteBuf)
```

- 尽量 **in-place / 写到预分配 buf**  
- 禁止每单元格 `format!` 大字符串  
- 算法注册表：`phone_mask`、`id_card_mask`、`hash_sha256`、`const_replace`

---

## 7. 数据路径演进（相对现状）

### 7.1 现状（问题）

```text
全量 rows: Vec<Vec<GatewayValue>>
全量 packets: Vec<Vec<u8>>
峰值 ≈ 2 × 结果集
```

### 7.2 目标热路径

```text
// Fast
backend_packet → client_socket   (可选旁路 audit L0)

// Secure
backend_row → mask/filter → encode_packet → client_socket
audit.try_send(meta)
```

### 7.3 兼容层

过渡期可保留 `GatewayResponse::ResultSet` 给小结果/测试；  
大结果与生产路径走 `StreamingQuery`。

---

## 8. 存储与查询（审计侧「快速查询」）

审计「查得快」和业务 SQL「查得快」是两件事：

| 需求 | 方案 |
|------|------|
| 在线检索最近 N 天 | 索引字段：time, subject, table, decision；存储 Elasticsearch / ClickHouse / PG 分区表 |
| 高吞吐写入 | 批量 insert / 本地 wal + 异步 ship |
| 长期合规 | 对象存储 + **Parquet 日分区**（冷） |
| 关联会话 | `session_id` + `trace_id`（OTel） |

**不要**用业务网关进程内嵌巨型分析库扛审计查询；控制面独立扩缩。

---

## 9. 容量与背压（粗算思路）

假设：

- 1 万 QPS，平均审计事件 500B（L0）→ 5 MB/s 写入，易扛  
- 若 L1 每条带 4KB SQL → 40 MB/s，需批量与采样  
- 若错误地 L3 全结果 → 与业务流量同量级，**不可持续**

因此架构必须：**默认 L0、义务触发 L1/L2、禁止默认 L3**。

---

## 10. 分阶段落地（与 S 路线对齐）

| 阶段 | 架构交付 | 性能交付 |
|------|----------|----------|
| **S0** | 事件 schema、异步 audit channel 骨架、security 配置空壳 | 主路径零阻塞发送 |
| **S1** | Subject、表级 PDP、Deny | 解析失败策略；无全量结果审计 |
| **S1.5 / 并行** | 流式 Result API + 同协议透传设计落地 | 低内存大数据基线 |
| **S2** | 列 ACL + AST 对象 | 策略缓存 |
| **S3** | 流式 mask/替换/去列 | Secure Path 性能基线 |
| **S4** | 审计持久化 + 检索 | 批量 sink；可选 Parquet 归档 |
| **S5** | Ticket/金库 | 高危同步最小审计 |
| **S6** | 通道/导出/门户 | 导出通道单独限流 |

**建议：S1 与「流式/透传」并行**，否则表级 ACL 仍建在全量 IR 上，大数据场景先崩。

---

## 11. 技术选型总结表

| 层级 | 选型 | 不选（现阶段） |
|------|------|----------------|
| 在线 IR | 行式流式 + 可选 `Bytes` | 全量 `Vec<Vec<GatewayValue>>` 作唯一模型 |
| 快路径 | 同协议 packet passthrough | Arrow 作代理 IR |
| 策略 | 自研 PDP 契约 + 可外置 | 全塞 plugin regex |
| 解析 | mysql_parser + sqlparser 统一 ObjectAccess | 仅启发式长期扛生产 ACL |
| 审计在线 | 异步队列 + 结构化日志/OTLP/批量 | 同步写盘 |
| 审计冷存 | 对象存储 + Parquet（S4+） | 热路径写 Parquet |
| 分析 | 独立 OLAP/检索 | 网关内嵌重分析引擎 |
| 脱敏 | 流式列函数 | 全表进内存再 mask |

---

## 12. 风险与原则清单

1. **审计不得默认复制结果集**  
2. **大查询必须流式 + 上限**  
3. **无义务走透传，有义务付费**  
4. **PDP 可缓存，义务执行在本地**  
5. **解析失败行为显式可配，生产偏 fail-closed**  
6. **管理面身份 ≠ 数据面 Subject**  
7. **新组件 default off，兼容现网 smoke**  

---

## 13. 结论

| 问题 | 答案 |
|------|------|
| 表/字段/行筛选打码替换要什么技术？ | **对象抽取 + PDP 义务 + 流式 Obligation Engine + 分级异步审计** |
| 高并发低内存靠什么？ | **透传快路径、流式窗口、有界队列、无全量 IR、策略缓存** |
| 要不要 Arrow/Parquet？ | **热路径不要**；冷归档/分析可用 Parquet，Arrow 仅分析场景 |
| 最新技术里什么值得上？ | **流式与透传、异步审计、可插拔 mask、策略版本缓存**；不是堆概念 |

**一句话**：  
高性能数据审计与安全改写的架构核心是 **「分级、异步、流式、可旁路」**——先把路径改对，再让脱敏/行过滤成为流上的廉价算子，而不是第二次把整个结果集搬进内存。

---

## 14. 下一步工程建议

1. **详设**：`StreamingQuery` / `RowStream` / `ResultSink` API（替换全量 `ResultSet`）  
2. **S0**：异步 `AuditEvent` 管道 + schema  
3. **S1**：表级 Deny + Subject  
4. **并行**：同协议 packet passthrough 原型  

修订记录：2026-07 初稿。
