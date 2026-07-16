# Admin 密码配置统一说明

管理面鉴权（**不是**数据面库表权限）。密码只用于 break-glass，生产优先 OIDC + JWKS。

## 两套「密码」不要混用

| 配置位置 | 变量 / 字段 | 作用 | 是否签发网关 JWT |
|----------|-------------|------|------------------|
| **Gateway** `admin_auth.break_glass_password` | TOML `[admin_auth]` | `POST /admin/auth/login` 换 HS256 Bearer | **是**（推荐） |
| **data-ui** `NUXT_PUBLIC_ADMIN_PASSWORD` | 构建/运行时 env | 仅 UI 本地门禁（legacy） | **否**（API 仍可能 401） |

### 推荐生产组合

```text
Admin API 鉴权:  enabled=true
  主路径:        mode=jwt_jwks + 企业 OIDC access_token
  应急:          break_glass_password + jwt_secret（HS256 换票）
data-ui:         OIDC 登录；密码登录走网关 /admin/auth/login
                 可不设 NUXT_PUBLIC_ADMIN_PASSWORD
```

### 推荐本地开发

```text
admin_auth.enabled = false     # Admin API 开放
NUXT_PUBLIC_ADMIN_PASSWORD 可空 # UI 无门禁
```

或本地也开鉴权：

```toml
[admin_auth]
enabled = true
mode = "jwt_hmac"
jwt_secret = "local-dev-secret-16"
break_glass_password = "local-dev-pass"
```

```bash
# UI 密码可与 gateway 相同，仅作提示；真正校验在网关
NUXT_PUBLIC_ADMIN_PASSWORD=local-dev-pass pnpm dev
```

UI 检测到 `break_glass_login: true` 时，密码框会调用网关换票并保存 `access_token`。

---

## Gateway 配置

见 `data-proxy/examples/admin-auth.snippet.toml`。

### HMAC（测试 / 无 IdP）

```toml
[admin_auth]
enabled = true
mode = "jwt_hmac"
jwt_secret = "change-me-to-a-long-random-secret"
issuer = "data-nexus"
audience = "data-nexus-admin"
break_glass_password = "change-me-break-glass"
break_glass_role = "admin"
token_ttl_secs = 3600
public_metrics = true
```

### JWKS（企业 OIDC）

```toml
[admin_auth]
enabled = true
mode = "jwt_jwks"
jwks_url = "https://idp.example.com/realms/ops/protocol/openid-connect/certs"
issuer = "https://idp.example.com/realms/ops"
audience = "data-nexus-admin"   # 与 IdP client / resource aud 对齐
jwks_cache_secs = 300
# 可选应急（需同时配 jwt_secret）
jwt_secret = "change-me-to-a-long-random-secret"
break_glass_password = "change-me-break-glass"
```

IdP 侧：

1. SPA public client（PKCE），`redirect_uri` 指向 data-ui `/auth/callback`
2. access_token 带 `aud`（或 API 关闭 audience 校验——不推荐）
3. groups/roles 映射到 `role_bindings`（如 `data-nexus-admins` → `admin`）

data-ui：

```bash
NUXT_PUBLIC_OIDC_ISSUER=https://idp.example.com/realms/ops \
NUXT_PUBLIC_OIDC_CLIENT_ID=data-nexus-admin \
NUXT_PUBLIC_OIDC_REDIRECT_URI=http://localhost:3000/auth/callback \
pnpm dev
```

UI 使用 OIDC **access_token** 调 Admin API；网关用 JWKS 验签。

---

## API 一览

| 方法 | 路径 | 鉴权 |
|------|------|------|
| GET | `/admin/auth/config` | 公开（是否启用、是否 break-glass） |
| POST | `/admin/auth/login` | 公开 body：`{"password":"..."}` → JWT |
| GET | `/admin/me` | Bearer |
| 其它 `/admin/*` | | Bearer + permission |
| GET | `/metrics` | 默认公开（`public_metrics=true`） |

---

## 迁移清单

1. 先开 `jwt_hmac` + break-glass，验证 UI 换票与 reload  
2. 配 IdP + `jwt_jwks`，OIDC 登录后确认 `/admin/me`  
3. 去掉 `NUXT_PUBLIC_ADMIN_PASSWORD`（避免误以为 API 已鉴权）  
4. 限制 Admin 端口网络暴露  

---

## 明确不做

- 用 UI 密码代替 API 鉴权  
- 数据面（SQL/库表）RBAC  
- 在浏览器本地伪造角色（角色以 `/admin/me` 为准）
