# Data Nexus 后续开发计划

详细架构见：`docs/data-nexus-protocol-gateway-plan.md`

## 产品定位

Data Nexus = **数据库协议中转站**（不是单协议 MySQL proxy）。

- 前端协议、后端协议、SQL 方言、路由、治理插件解耦
- Phase A/B：同协议中转；Phase C：治理协议无关；Phase D：受控跨协议

---

## 现状快照（2026-07）

### 已完成

- M0–M8：网关主路径、跨协议、方言 AST、嵌入式 Admin、Nuxt UI、OTel traces/metrics/logs
- `data-ui`：多页路由 + 可选密码登录
- 文档：`data-proxy/examples/OBSERVABILITY.md`、`data-ui/README.md`

### 开放缺口（可选）

1. data-ui 生产部署打包 / SSO
2. OTel 自定义业务 metrics 与 trace 采样策略

---

## 路线总览

```text
M0–M4  核心网关 + 跨协议 + 方言/可观测   ✓
M5     Admin UI + 可选 OTel              ✓
M6     PostgreSQL AST dialect            ✓
M7     data-ui Nuxt + Admin CORS         ✓
M8     OTel metrics/logs + UI 路由/认证  ✓
```

---

## 验收跑法

| 场景 | 命令 |
|------|------|
| 同协议双 listener | `./data-proxy/examples/smoke-dual-listener.sh` |
| MySQL → PG | `./data-proxy/examples/smoke-cross-protocol.sh` |
| PG → MySQL | `./data-proxy/examples/smoke-cross-protocol-pg-to-mysql.sh` |
| 嵌入式 Admin | `http://127.0.0.1:8082/admin` |
| Nuxt Admin | `cd data-ui && pnpm dev` |
| OTel | `cargo build -p data-proxy --features otel` + `OTEL_EXPORTER_OTLP_ENDPOINT` |

---

## M8：OTel metrics/logs + data-ui 认证/路由（完成）

### OTel

- [x] traces（原有）
- [x] metrics：`MetricExporter` + `PeriodicReader`（`DATA_NEXUS_OTEL_METRICS=0` 关闭）
- [x] logs：`LogExporter` + `opentelemetry-appender-tracing2`（`DATA_NEXUS_OTEL_LOGS=0` 关闭）
- [x] 启动计数器 `data_nexus.otel.up`
- [x] 默认构建仍不依赖 OTel SDK

### data-ui

- [x] 路由：`/` overview、`/topology`、`/sessions`、`/settings`、`/login`
- [x] 布局 `layouts/admin.vue` + 导航
- [x] 可选密码：`NUXT_PUBLIC_ADMIN_PASSWORD` + localStorage 会话 12h
- [x] 全局 middleware `auth.global.ts`

---

## 模块边界

```text
gateway/core     协议无关类型
runtime/gateway  编排 + dialect + spans
cmd/pisa         进程入口、日志 / 可选 OTel（traces+metrics+logs）
http             Admin API + /admin HTML + CORS
data-ui          Nuxt 管理台（多页 + 可选登录）
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
