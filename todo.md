# Data Nexus 后续开发计划

详细架构见：`docs/data-nexus-protocol-gateway-plan.md`

## 产品定位

Data Nexus = **数据库协议中转站**（不是单协议 MySQL proxy）。

- 前端协议、后端协议、SQL 方言、路由、治理插件解耦
- Phase A/B：同协议中转；Phase C：治理协议无关；Phase D：受控跨协议

---

## 现状快照（2026-07）

### 已完成

- M0–M6：同/跨协议 E2E、方言 AST、tracing、嵌入式 Admin、可选 OTel
- `data-ui` Nuxt 管理台消费 Admin API + CORS
- 文档：`data-proxy/examples/OBSERVABILITY.md`、`data-ui/README.md`

### 开放缺口（可选）

1. OTel metrics/logs 导出（当前仅 traces）
2. data-ui 路由拆分 / 认证 / 生产部署打包

---

## 路线总览

```text
M0–M4  核心网关 + 跨协议 + 方言/可观测   ✓
M5     Admin UI + 可选 OTel              ✓
M6     PostgreSQL AST dialect            ✓
M7     data-ui Nuxt + Admin CORS         ✓
```

---

## 验收跑法

| 场景 | 命令 |
|------|------|
| 同协议双 listener | `./data-proxy/examples/smoke-dual-listener.sh` |
| MySQL → PG | `./data-proxy/examples/smoke-cross-protocol.sh` |
| PG → MySQL | `./data-proxy/examples/smoke-cross-protocol-pg-to-mysql.sh` |
| 嵌入式 Admin | `http://127.0.0.1:8082/admin` |
| Nuxt Admin | `cd data-ui && pnpm dev`（`NUXT_PUBLIC_ADMIN_API_BASE`） |
| OTel | `cargo build -p data-proxy --features otel` + `OTEL_EXPORTER_OTLP_ENDPOINT` |

---

## M7：data-ui + CORS（完成）

- [x] Nuxt 管理台：listeners/services/endpoints/pools/sessions + reload
- [x] `composables/useAdminApi.ts` + 可配置 API base
- [x] Admin API CORS（默认 any；`DATA_NEXUS_ADMIN_CORS_ORIGINS` 可收紧）
- [x] CORS 单测
- [x] README / OBSERVABILITY 文档

---

## 模块边界

```text
gateway/core     协议无关类型
runtime/gateway  编排 + dialect + spans
cmd/pisa         进程入口、日志 / 可选 OTel
http             Admin API + /admin HTML + CORS
data-ui          Nuxt 管理台（消费 Admin API）
```

---

## 暂不做

- [ ] 任意方言全量互转
- [ ] 默认构建硬依赖 OTel SDK
- [ ] 用 `node_type` 字符串决定运行时行为

---

## 完成定义

1. 示例 config 或集成测试
2. 相关 `cargo test` / `cargo check` 通过
3. 无新主路径 `unwrap()` / 字符串协议分支
4. 更新本文件
