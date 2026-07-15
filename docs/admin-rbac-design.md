# Admin IdP 角色映射与 RBAC 设计

状态：**Phase 1 部分已实现（管理面轻量鉴权）**  
关联：`data-ui` OIDC 登录、`data-proxy/http` Admin API  
日期：2026-07

> 产品边界：仅 **Admin 运维鉴权**，不做数据防水坝式库表 RBAC。

---

## 1. 问题与现状

### 现状

| 层 | 能力 | 安全边界 |
|----|------|----------|
| data-ui 密码 | 浏览器 localStorage 会话 | **仅 UI 门禁** |
| data-ui OIDC | PKCE 换 token，存 access/id token | **仅 UI 门禁**；token 未带给 Admin API |
| Admin HTTP | `/admin/*` 无 Bearer / cookie 校验 | **任何能访问 admin 端口的人可读写** |

结论：当前 SSO 解决的是「谁能打开管理台」，**不是**「谁能改网关配置」。生产若 Admin 端口可达，必须在 **gateway 侧**做鉴权，不能只靠前端隐藏按钮。

### 目标

1. 从 IdP 声明（claims）映射到 Data Nexus **角色**
2. 角色映射到 **权限**（RBAC）
3. **UI + Admin API 双端一致**（API 为权威）
4. 默认安全：未配置 auth 时保持现状（dev 友好）；生产显式开启

### 非目标（首期不做）

- 细粒度到单个 listener/service 的 ABAC（可二期）
- 多租户组织隔离
- 用户表 / 本地账号体系（密码仅作 break-glass）
- 完整 OAuth resource server 的动态 scope 协商

---

## 2. 威胁模型（简要）

| 威胁 | 缓解 |
|------|------|
| 未授权读配置/会话 | API 强制 Bearer；无 token → 401 |
| 未授权 reload / 改路由 | 写权限校验；无权限 → 403 |
| 伪造前端角色 | 角色只信 **JWT 校验后的 claims**，不信 localStorage 里的 role 字段 |
| Token 泄漏 | 短 TTL、HTTPS、不把 token 打日志；UI 仅 memory/sessionStorage 可选加固 |
| Admin 端口暴露 | 网络隔离 + 强制 `admin_auth.enabled` |
| 密码用户绕过 OIDC | break-glass 账号映射固定最高角色，并记 audit |

---

## 3. 角色与权限模型

### 3.1 内置角色（固定集合，首期）

| 角色 | 含义 | 典型 IdP 人群 |
|------|------|----------------|
| `viewer` | 只读运维 | 值班、业务方 |
| `operator` | 日常运维（不停服务的操作） | on-call |
| `admin` | 变更配置 / 生命周期 | 平台管理员 |

密码登录（break-glass）默认映射：`admin`（可配置）。

### 3.2 权限（permission）原子

命名：`resource:action`

| Permission | 说明 | 典型 API |
|------------|------|----------|
| `topology:read` | 读 listeners/services/endpoints/config | GET `/admin/listeners\|services\|endpoints\|config` |
| `runtime:read` | 读 pools/sessions/metrics 元数据 | GET `/admin/pools\|sessions` |
| `runtime:refresh` | 刷新连接池 | POST `/admin/pools/**/refresh` |
| `listener:control` | 停 listener | POST `/admin/listeners/:name/stop` |
| `listener:write` | 增 listener | POST `/admin/listeners` |
| `policy:write` | 改 route policy | PUT `/admin/route-policies/:name` |
| `config:reload` | 热加载配置 | POST `/admin/reload` |
| `metrics:read` | 拉 Prometheus | GET `/metrics`（可选纳入，见下） |

**角色 → 权限（默认矩阵）**

| Permission | viewer | operator | admin |
|------------|:------:|:--------:|:-----:|
| topology:read | ✓ | ✓ | ✓ |
| runtime:read | ✓ | ✓ | ✓ |
| metrics:read | ✓ | ✓ | ✓ |
| runtime:refresh | | ✓ | ✓ |
| listener:control | | ✓ | ✓ |
| listener:write | | | ✓ |
| policy:write | | | ✓ |
| config:reload | | | ✓ |

说明：

- `metrics:read` 默认与 viewer 对齐；若 metrics 已在独立网络，可配置 `public_metrics = true` 跳过鉴权（兼容现有 scrape）。
- 嵌入式 `GET /admin` HTML 页：与 UI 相同，需要 token 时改为「登录后注入」或仅内网使用（见 6.3）。

### 3.3 扩展方式

- 首期 **不支持**自定义角色名进代码；只支持：
  - IdP group/role **字符串 → 内置角色** 映射表
  - 可选：某角色 **额外附加 permission**（配置级，少用）
- 二期：`custom_roles` + permission 列表

---

## 4. IdP Claims 映射

### 4.1 输入 claims（可配置路径）

常见 IdP 字段（按优先级尝试）：

1. `realm_access.roles`（Keycloak）
2. `resource_access.<client_id>.roles`（Keycloak client roles）
3. `groups`（Auth0 / Okta / Azure 常映射）
4. `roles`（扁平数组）
5. 自定义：`https://data-nexus.io/roles`

配置示例（目标 v2 片段，**尚未落地**）：

```toml
[admin_auth]
enabled = true
# jwt | none（none = 现状，仅 dev）
mode = "jwt"

[admin_auth.jwt]
# 二选一：JWKS URL（推荐）或静态 HMAC（仅测试）
jwks_url = "https://idp.example.com/realms/ops/protocol/openid-connect/certs"
issuer = "https://idp.example.com/realms/ops"
audience = "data-nexus-admin"
# 时钟 skew 秒
leeway_secs = 60

[admin_auth.claim_mapping]
# claim 路径，点号分隔；支持多路径，并集
role_claim_paths = [
  "realm_access.roles",
  "groups",
  "roles",
]
# IdP 值 → 内置角色（大小写不敏感匹配）
[admin_auth.claim_mapping.bindings]
"data-nexus-admins" = "admin"
"data-nexus-operators" = "operator"
"data-nexus-viewers" = "viewer"
"platform-admin" = "admin"

[admin_auth.password_break_glass]
# 可选：与现有静态密码并存时的角色
role = "admin"

[admin_auth.metrics]
# scrape 是否免鉴权
public = true
```

### 4.2 映射算法

```
claims → extract string sets from role_claim_paths
      → foreach value: lookup bindings (case-insensitive)
      → 得到 Role 集合 R
      → 有效角色 = max(R)   # admin > operator > viewer
      → 若 R 为空 → 403 insufficient_role（已认证但无映射）
```

**多角色取高**：用户同时有 viewer+admin → admin。  
**无匹配**：已登录但未绑定 → 拒绝（避免默认升权）。

### 4.3 UI 与 IdP 对齐

- UI OIDC `client_id` 与 API `audience` 建议一致或 API 接受多个 audience。
- UI 在拿到 `access_token` 后：
  1. 调 `GET /admin/me` 拿服务端解析的 `roles` / `permissions`（权威）
  2. 本地只做菜单隐藏；**写操作失败以 403 为准**
- 不在浏览器解析 JWT 做授权决策（可解析仅展示 display name）。

### 4.4 Token 选择

| Token | 用途 |
|-------|------|
| **access_token**（推荐） | 调 Admin API：`Authorization: Bearer <access_token>` |
| id_token | 仅 UI 展示身份；**不要**单独作为 API 凭证（除非 audience 明确包含 API） |

IdP 需为 SPA public client 签发带正确 `aud` 的 access token（或 Resource Indicator / audience 配置）。

---

## 5. 架构

```text
Browser data-ui
  │  OIDC PKCE → IdP
  │  access_token
  ▼
Admin API (data-proxy/http)     ◄── 权威鉴权
  │  1. 可选：CORS + Bearer
  │  2. JWT validate (JWKS)
  │  3. claim → role → permission
  │  4. route 声明 required permission
  ▼
Runtime / Config
```

```text
                    ┌─────────────────────┐
                    │  admin_auth middleware │
                    │  extract Bearer        │
                    │  verify JWT            │
                    │  map roles             │
                    │  inject AuthContext    │
                    └──────────┬──────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
   GET topology          POST reload           GET /metrics
   need topology:read    need config:reload    public or metrics:read
```

### 5.1 AuthContext（gateway 内）

```rust
// 设计形状，非最终代码
struct AuthContext {
    subject: String,           // sub
    roles: Vec<AdminRole>,     // 已映射内置角色
    permissions: HashSet<Permission>,
    auth_method: Jwt | BreakGlass | Disabled,
}
```

### 5.2 路由鉴权表（与现有 API 对齐）

| Method | Path | Permission |
|--------|------|------------|
| GET | `/admin/config` | topology:read |
| GET | `/admin/listeners` | topology:read |
| GET | `/admin/services` | topology:read |
| GET | `/admin/endpoints` | topology:read |
| GET | `/admin/pools` | runtime:read |
| GET | `/admin/sessions` | runtime:read |
| GET | `/admin/me` | （已认证即可） |
| POST | `/admin/pools/refresh` | runtime:refresh |
| POST | `/admin/pools/:name/refresh` | runtime:refresh |
| POST | `/admin/listeners/:name/stop` | listener:control |
| POST | `/admin/listeners` | listener:write |
| PUT | `/admin/route-policies/:name` | policy:write |
| POST | `/admin/reload` | config:reload |
| GET | `/admin` HTML | topology:read（或仅内网） |
| GET | `/metrics` | metrics:read 或 public |
| GET | `/healthz` `/version` | **始终公开** |

### 5.3 新增 API

| Method | Path | 说明 |
|--------|------|------|
| GET | `/admin/me` | 返回 `{ sub, roles, permissions, auth_method }` |
| GET | `/admin/auth/config` | 公开：`{ enabled, mode, oidc_hint? }` 供 UI 判断是否需登录 |

`/admin/auth/config` **不**返回密钥；仅 UI 启动探测。

---

## 6. UI 行为

### 6.1 鉴权状态机

```
未配置 auth     → 全开（与现在一致）
仅密码          → 密码登录 → 会话 role=admin（break-glass）
仅 OIDC         → SSO → Bearer → /admin/me
密码 + OIDC     → 登录页双入口
```

### 6.2 基于权限的 UI

| 区域 | 控制 |
|------|------|
| Overview / Topology / Sessions 只读表 | `topology:read` / `runtime:read` |
| Settings → Reload | `config:reload` |
| （未来）Stop listener 按钮 | `listener:control` |
| 无权限 | 隐藏操作 + 深链访问显示 403 页 |

### 6.3 嵌入式 `/admin` HTML

选项（实现时二选一，推荐 A）：

- **A.** `admin_auth.enabled` 时嵌入页仅展示「请使用 data-ui」+ 链接，避免无 token 的静态页误用  
- **B.** 支持 `?token=` 查询参数（**不推荐**，易进 referrer）

### 6.4 API 客户端改造

`useAdminApi` 所有请求附加：

```http
Authorization: Bearer <access_token>
```

密码模式：gateway 提供 `POST /admin/auth/token` 交换短 JWT（HMAC 本地签发），或密码模式仅允许 loopback（实现阶段再定）。  
**推荐密码 break-glass 也走 gateway 签发的短期 JWT**，避免「密码模式完全不鉴权 API」。

---

## 7. 密码 Break-glass 设计

| 项 | 建议 |
|----|------|
| 配置 | `admin.password` 或现有 UI 密码迁到 gateway 配置 |
| 换票 | `POST /admin/auth/login` `{ password }` → `{ access_token, expires_in }` |
| 角色 | 固定 `admin`（可配） |
| Audit | `auth_method=break_glass` 写入 audit 日志 |
| 限制 | 可选：仅 `127.0.0.1` / 私网 CIDR |

这样 API 始终只认 JWT，中间件统一。

---

## 8. 分阶段落地（建议）

### Phase 0 — 设计确认（本文）

- [ ] 角色/权限矩阵确认
- [ ] IdP claim 路径与 binding 示例确认
- [ ] metrics 是否 public 确认
- [ ] 密码 break-glass 是否强制换 JWT 确认

### Phase 1 — API 鉴权骨架（网关）— **进行中 / 已落地 HMAC**

1. [x] `admin_auth` 配置解析 + validate（`GatewayConfigDocument.admin_auth`）  
2. [x] JWT HS256（`mode = jwt_hmac`）+ issuer/audience 可选校验  
3. [x] 角色/权限模型 + 路由 permission 表  
4. [x] `GET /admin/me`、`GET /admin/auth/config`  
5. [x] `admin_auth.enabled=false` 时兼容现网  
6. [x] 单测：无 token / viewer 禁止 reload / admin 可读 me  
7. [ ] JWKS（`jwt_jwks` 模式，接企业 IdP access_token）— Phase 1b  
8. [ ] UI 自动带 Bearer — Phase 2  

**配置示例（HMAC，运维/测试）：**

```toml
[admin_auth]
enabled = true
mode = "jwt_hmac"
jwt_secret = "please-use-a-long-random-secret"
issuer = "data-nexus"
audience = "data-nexus-admin"
public_metrics = true
```

发 token（库内 `issue_hmac_token`，后续可加 `POST /admin/auth/login`）。

**退出标准**：enabled 时无 token 无法 reload；viewer token 无法 reload。

### Phase 2 — UI 对接

1. token 附加到 Admin API  
2. 启动拉 `/admin/me` 驱动菜单  
3. OIDC 登录后必须成功调 `/admin/me` 才算登录完成  
4. 403 页面  

### Phase 3 — Break-glass 换票

1. `POST /admin/auth/login`  
2. UI 密码登录改走换票  
3. 废弃「仅 UI 密码、API 裸奔」路径  

### Phase 4 — 加固（可选）

1. listener 级 ABAC（claim `allowed_listeners`）  
2. Audit 全量写操作带 `sub` + role  
3. mTLS 管理口  
4. 嵌入式 admin 页策略 A  

---

## 9. 配置与环境变量对照

| 概念 | 配置 / Env（建议） |
|------|-------------------|
| 总开关 | `admin_auth.enabled` / `DATA_NEXUS_ADMIN_AUTH=1` |
| JWKS | `admin_auth.jwt.jwks_url` |
| Issuer | `admin_auth.jwt.issuer` |
| Audience | `admin_auth.jwt.audience` |
| Role claims | `admin_auth.claim_mapping.role_claim_paths` |
| Bindings | `admin_auth.claim_mapping.bindings` |
| Metrics public | `admin_auth.metrics.public` |
| UI OIDC | 现有 `NUXT_PUBLIC_OIDC_*`（client） |
| UI 密码 | 逐步改为调 gateway login，而非仅前端比对 |

**原则**：密钥与 JWKS 只在 gateway；UI 仍可持有 public client_id。

---

## 10. 兼容性与迁移

| 环境 | 行为 |
|------|------|
| 本地 dev 无 `admin_auth` | 与现在完全一致 |
| 仅开 UI 密码、未开 API auth | **不安全**；文档标明 deprecated，Phase 3 消除 |
| 生产 | `admin_auth.enabled=true` + 网络策略 + OIDC |

迁移步骤建议：

1. IdP 建 groups：`data-nexus-viewers|operators|admins`  
2. 配 bindings，enabled=true 在预发验证  
3. UI 发版带 Bearer  
4. 再关公网对 admin 端口的无鉴权访问  

---

## 11. 测试计划（实现时）

| 用例 | 期望 |
|------|------|
| enabled=false，无 token GET listeners | 200 |
| enabled=true，无 token POST reload | 401 |
| viewer token POST reload | 403 |
| admin token POST reload | 200（配置合法时） |
| 错误 issuer/aud | 401 |
| groups 映射 operator | 可 refresh pool，不可 add listener |
| `/admin/me` | 返回映射后 roles/permissions |
| 过期 JWT | 401 |

---

## 12. 待决策项（请确认后再编码）

1. **metrics**：默认 `public=true` 还是纳入 RBAC？  
2. **多角色**：确认「取最高」而非 permission 并集？（并集更灵活，矩阵需改）  
3. **密码 break-glass**：是否 Phase 1 就强制换 JWT？  
4. **JWKS 库**：`jsonwebtoken` + `jwks-retriever` 或 `jose` 生态，需符合当前 Rust 版本  
5. **嵌入式 HTML admin**：enabled 时禁用还是保留内网免鉴权？  
6. **audience**：与 UI `client_id` 是否强制同一字符串？  

---

## 13. 建议默认决策（若无额外反馈）

| 项 | 默认 |
|----|------|
| 多角色 | **permission 并集**（比单 max 更直观；viewer+operator=operator 权限） |
| metrics | **public=true**（兼容 Prometheus scrape） |
| break-glass | Phase 1 只做 JWT；Phase 3 再换票 |
| 嵌入式 admin | enabled 时返回 401/引导页 |
| 无映射角色 | 403 `no_mapped_role` |

**并集说明**：bindings 命中多个内置角色时，permissions = ∪(role permissions)，而不是只留一个角色名；`/admin/me` 仍返回全部 hit 的 roles 便于展示。

---

## 14. 文档与代码落点（实现时）

| 组件 | 路径 |
|------|------|
| 设计 | `docs/admin-rbac-design.md`（本文） |
| 配置类型 | `gateway_core` 或 `app/config` 的 `AdminAuthConfig` |
| 中间件 | `http/src/http/auth.rs` |
| UI | `useAdminAuth` / `useAdminApi` / 路由 meta `requiredPermissions` |
| 观测 | audit：`sub`, `roles`, `permission`, `path`, `result` |

---

## 15. 小结

- **权威在 Admin API**，UI 只做体验层。  
- **三角色 + 明确 permission 矩阵**，IdP 只做字符串绑定。  
- **JWT Bearer + JWKS**，OIDC 与 break-glass 最终都收敛到同一种凭证。  
- **分四阶段**，Phase 1 即可堵住最大风险（裸 API）。  

确认第 12 节决策项后，可按 Phase 1 开工实现。
