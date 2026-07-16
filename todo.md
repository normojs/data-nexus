# Data Nexus 后续开发计划

详细架构见：`docs/data-nexus-protocol-gateway-plan.md`  
数据安全升级见：`docs/data-security-roadmap.md`

## 产品定位

Data Nexus = **数据库协议中转站** + 规划中的 **数据访问安全能力**（PEP）。

- L0：前端/后端协议、方言、路由、治理、观测（M0–M10 已完成）
- L1：数据面身份、表/列/行授权、脱敏、审批、通道管控（S0–S6，见路线图）
- 管理面鉴权（Admin RBAC）与数据面授权 **分离**
- 对标参考：美创数据防水坝、数安 SQLDev（竞争 + 差异化：协议原生 PEP）

---

## 现状快照（2026-07）

### 已完成（L0 + 管理面）

- 同/跨协议 E2E、方言 AST、Admin API、data-ui、OTel
- Admin：`jwt_hmac` / `jwt_jwks`、break-glass、UI Bearer、`smoke-admin-auth.sh`

### 数据安全（L1）— 按路线图推进

| 阶段 | 主题 | 状态 |
|------|------|------|
| S0 | 边界修订 + 审计模型 + security 配置空壳 | 待办 |
| S1 | Subject + 语句/表级 Deny MVP | 待办 |
| S2 | AST 对象抽取 + 表/列 ACL | 待办 |
| S3 | ResultSet 钩子 + 动态脱敏（+ 行/水印雏形） | 待办 |
| S4 | 持久化审计 + 查询 API/UI | 待办 |
| S5 | 审批/金库 + 通道高危门闩 | 待办 |
| S6 | 门户/环境/Vault/导出运营 | 待办 |

### 开放缺口（L0 运维增强，可选）

1. OTel span 自定义 attributes 与按 service 采样  
2. data-ui 403 友好页  

### 早期非目标（S0–S2）

- 一次做齐防水坝全家桶  
- 任意方言全量互转  
- Admin JWT 直接当数据面身份  
- 默认 fail-open 且无指标  

---

## 路线总览

```text
M0–M10  协议网关 + 管理面鉴权 + UI + 观测     ✓
S0–S6   数据安全（对标防水坝/SQLDev 的升级）  规划中
```

---

## 验收跑法（L0）

| 场景 | 命令 |
|------|------|
| 同协议双 listener | `./data-proxy/examples/smoke-dual-listener.sh` |
| MySQL → PG | `./data-proxy/examples/smoke-cross-protocol.sh` |
| PG → MySQL | `./data-proxy/examples/smoke-cross-protocol-pg-to-mysql.sh` |
| Admin 鉴权 | `./data-proxy/examples/smoke-admin-auth.sh` |
| Nuxt / Docker UI | 见 `data-ui/README.md` |

---

## M10：管理面鉴权（完成）

- [x] HMAC / JWKS、break-glass、UI Bearer、`/admin/me`  
- [x] `smoke-admin-auth.sh`  
- 文档：`docs/admin-rbac-design.md`、`docs/admin-auth-password.md`  

---

## S0：数据安全启动（下一工程里程碑）

详见 `docs/data-security-roadmap.md` §6–§7。

- [ ] `todo` / 路线图边界与团队对齐  
- [ ] `SecurityPolicyConfig` 空壳 + validate（default off）  
- [ ] 统一 `data_nexus::audit` 字段 schema  
- [ ] Admin 写操作 audit 带 `sub`  
- [ ] 现有 smoke 在 default off 下全绿  

---

## 模块边界

```text
gateway/core     协议无关类型 + AdminAuth +（规划）Security 类型
runtime/gateway  PEP：编排 + dialect + 策略执行 + 结果改写
policy / workflow（规划）  PDP / 工单（可进程内后拆分）
http             Admin API（管理面）
data-ui          运维台 → 逐步扩展策略/审计/工单
```

---

## 完成定义

1. 示例 config 或 smoke  
2. 相关 `cargo test` / `cargo check` 通过  
3. 无新主路径 panic；数据安全 default off 兼容  
4. 更新本文件与 `docs/data-security-roadmap.md`  
