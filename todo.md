# Data Nexus 后续开发计划

详细架构见：`docs/data-nexus-protocol-gateway-plan.md`

## 产品定位

Data Nexus = **数据库协议中转站**（不是单协议 MySQL proxy）。

- 前端协议、后端协议、SQL 方言、路由、治理插件解耦
- Phase A/B：同协议中转；Phase C：治理协议无关；Phase D：受控跨协议
- 管理面轻量鉴权；**不做**数据面库表 RBAC（对标防水坝/SQLDev）

---

## 现状快照（2026-07）

### 已完成

- M0–M10：同/跨协议 E2E、方言 AST、Admin API、data-ui、OTel、管理面鉴权
- Admin 鉴权：`jwt_hmac` / `jwt_jwks`、break-glass 换票、UI Bearer、`/admin/me`
- 文档：`docs/admin-rbac-design.md`、`docs/admin-auth-password.md`、`examples/OBSERVABILITY.md`

### 开放缺口（可选）

1. OTel：span 自定义 attributes 与按 service 采样覆盖  
2. Admin 写操作 audit 带 `sub` / role  
3. data-ui 403 友好页  

### 明确不做

- 数据面库表/列 RBAC、审批工单、脱敏中心  
- 任意方言全量互转  
- 默认构建硬依赖 OTel SDK  

---

## 路线总览

```text
M0–M4  核心网关 + 跨协议 + 方言/可观测   ✓
M5–M8  Admin / Nuxt / OTel 基础          ✓
M9     生产打包 + SSO + 采样/业务指标    ✓
M10    管理面鉴权（轻量 RBAC）           ✓
```

---

## 验收跑法

| 场景 | 命令 |
|------|------|
| 同协议双 listener | `./data-proxy/examples/smoke-dual-listener.sh` |
| MySQL → PG | `./data-proxy/examples/smoke-cross-protocol.sh` |
| PG → MySQL | `./data-proxy/examples/smoke-cross-protocol-pg-to-mysql.sh` |
| **Admin 鉴权** | `./data-proxy/examples/smoke-admin-auth.sh` |
| 嵌入式 Admin | `http://127.0.0.1:8082/admin` |
| Nuxt dev | `cd data-ui && pnpm dev` |
| Nuxt 生产镜像 | `cd data-ui && docker build -t data-nexus-ui .` |
| OTel | `--features otel` + `OTEL_EXPORTER_OTLP_ENDPOINT` |

---

## M10：管理面鉴权（完成）

设计：`docs/admin-rbac-design.md`（边界：只管 Admin API，不管库表列）。

- [x] `AdminAuthConfig` / roles / permissions / 路由表  
- [x] `jwt_hmac` + claim 映射  
- [x] `jwt_jwks` + JWKS 缓存 + RS256  
- [x] Admin 路由鉴权；`enabled=false` 兼容  
- [x] `GET /admin/me`、`GET /admin/auth/config`  
- [x] `POST /admin/auth/login` break-glass  
- [x] data-ui Bearer + Settings 按 permission 裁剪  
- [x] 密码配置统一文档  
- [x] E2E smoke：`examples/smoke-admin-auth.sh` + `admin-auth-gateway-config.toml`  

---

## M9：生产打包 / SSO / OTel（完成）

- data-ui Docker/nginx、OIDC PKCE、OTel traces/metrics/logs + 采样 + 业务指标  

---

## 模块边界

```text
gateway/core     协议无关类型 + AdminAuth 模型
runtime/gateway  编排 + dialect + spans + 可选 OTel 业务 metrics
cmd/pisa         进程入口、OTLP exporter + 采样
http             Admin API + 鉴权 + /admin HTML + CORS
data-ui          Nuxt SPA（密码换票 / OIDC / Docker 生产）
```

---

## 完成定义

1. 示例 config 或集成 / smoke 测试  
2. 相关 `cargo test` / `cargo check` 通过  
3. 无新主路径 `unwrap()` / 字符串协议分支  
4. 更新本文件  
