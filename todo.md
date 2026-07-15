# Data Nexus 后续开发计划

详细架构见：`docs/data-nexus-protocol-gateway-plan.md`

## 产品定位

Data Nexus = **数据库协议中转站**（不是单协议 MySQL proxy）。

- 前端协议、后端协议、SQL 方言、路由、治理插件解耦
- Phase A/B：同协议中转；Phase C：治理协议无关；Phase D：受控跨协议

---

## 现状快照（2026-07）

### 已完成

- M0–M4：同/跨协议 E2E、方言、tracing JSON、双向 smoke
- Admin 自包含状态页：`GET /admin`
- 可选 OTel OTLP：`--features otel` + `OTEL_EXPORTER_OTLP_ENDPOINT`
- 文档：`data-proxy/examples/OBSERVABILITY.md`

### 开放缺口（可选）

1. 更完整的 PostgreSQL AST crate（structured classifier 已覆盖路由主路径）
2. 独立 `data-ui` Nuxt 应用深化（Admin HTML 页已可用）
3. OTel metrics/logs 导出（当前仅 traces）

---

## 路线总览

```text
M0–M4  核心网关 + 跨协议 + 方言/可观测   ✓
M5     Admin UI + 可选 OTel              ✓
```

---

## 验收跑法

| 场景 | 命令 |
|------|------|
| 同协议双 listener | `./data-proxy/examples/smoke-dual-listener.sh` |
| MySQL → PG | `./data-proxy/examples/smoke-cross-protocol.sh` |
| PG → MySQL | `./data-proxy/examples/smoke-cross-protocol-pg-to-mysql.sh` |
| Admin UI | 启动后打开 `http://127.0.0.1:8082/admin` |
| OTel | `cargo build -p data-proxy --features otel` + `OTEL_EXPORTER_OTLP_ENDPOINT` |

---

## M5：Admin UI + OTel（完成）

- [x] `GET /admin` 自包含 dashboard（listeners/services/endpoints/pools/sessions + reload）
- [x] 单测：dashboard 返回 HTML
- [x] 可选 feature `otel`（默认关闭，不拖累默认构建）
- [x] 运行时需 `OTEL_EXPORTER_OTLP_ENDPOINT` 才激活 OTLP
- [x] OBSERVABILITY.md 更新

---

## 模块边界

```text
gateway/core     协议无关类型
runtime/gateway  编排 + dialect + spans
cmd/pisa         进程入口、日志 / 可选 OTel
http             Admin API + /admin HTML
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
