# Data Nexus 后续开发计划

详细架构见：`docs/data-nexus-protocol-gateway-plan.md`

## 产品定位

Data Nexus = **数据库协议中转站**（不是单协议 MySQL proxy）。

- 前端协议、后端协议、SQL 方言、路由、治理插件解耦
- Phase A/B：同协议中转；Phase C：治理协议无关；Phase D：受控跨协议

---

## 现状快照（2026-07）

### 已完成

- M0–M9：网关主路径、跨协议、方言 AST、Admin、Nuxt UI、OTel 全链路
- data-ui：生产 Docker/nginx 打包 + OIDC PKCE SSO + 密码登录
- OTel：traces 采样策略 + 命令路径业务 metrics + logs

### 开放缺口（可选）

1. data-ui SSO：IdP 角色映射 / RBAC
2. OTel 自定义 span attributes 与采样策略按 service 覆盖

---

## 路线总览

```text
M0–M4  核心网关 + 跨协议 + 方言/可观测   ✓
M5–M8  Admin / Nuxt / OTel 基础          ✓
M9     生产打包 + SSO + 采样/业务指标    ✓
```

---

## 验收跑法

| 场景 | 命令 |
|------|------|
| 同协议 / 跨协议 smoke | `data-proxy/examples/smoke-*.sh` |
| 嵌入式 Admin | `http://127.0.0.1:8082/admin` |
| Nuxt dev | `cd data-ui && pnpm dev` |
| Nuxt 生产镜像 | `cd data-ui && docker build -t data-nexus-ui .` |
| OTel | `--features otel` + `OTEL_EXPORTER_OTLP_ENDPOINT` + sampler env |

---

## M9：生产打包 / SSO / OTel 策略（完成）

### data-ui 生产

- [x] `ssr: false` + `nuxt generate` 静态产物
- [x] `Dockerfile` multi-stage（pnpm generate → nginx）
- [x] `deploy/nginx.conf` SPA fallback + `/healthz`
- [x] `deploy/docker-compose.ui.yml`

### SSO

- [x] OIDC authorization code + PKCE（public client）
- [x] `/auth/callback` + discovery
- [x] 与密码登录可并存；均未配置则无门禁

### OTel

- [x] Sampler：`OTEL_TRACES_SAMPLER` / `DATA_NEXUS_OTEL_TRACES_SAMPLER` + ARG
- [x] 业务指标：`data_nexus.gateway.commands` / `command_duration_ms` / `errors`
- [x] feature 透传：`data-proxy/otel` → `runtime_gateway/otel`

---

## 模块边界

```text
gateway/core     协议无关类型
runtime/gateway  编排 + dialect + spans + 可选 OTel 业务 metrics
cmd/pisa         进程入口、OTLP exporter + 采样
http             Admin API + /admin HTML + CORS
data-ui          Nuxt SPA（密码 / OIDC / Docker 生产）
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
