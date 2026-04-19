# 客户端认证说明（索引版）

状态：索引文档

## 1. 说明

- 客户端认证链路与启动链路已统一归口到 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`（第 7 章）。
- 当前客户端在 `lib/main.dart` 里通过 `MonitoringDataSource` 和 `kServerBaseUrl` 选择 mock / HTTP 客户端。
- 认证会话由 `PersistentAuthSessionStore` 做本地持久化，重启后会恢复登录标识和会话信息。
- 全局约定（UUID、密钥、配置生命周期）见 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`。
- 边缘端认证与上传接口契约文档待重建（当前暂时下线）。

## 2. 客户端边界（保留）

- 客户端不参与本地密钥 bootstrap。
- 客户端仅通过网关进行登录、续期、校验、登出相关请求。
- 用户实体 ID 仅由后端认证结果返回。
- 认证会话只做简单本地持久化，不引入额外加密依赖；退出登录会清空本地会话。
- 客户端到网关链路的传输安全遵循网关对外协议约束（HTTPS/TLS）；后端模块间 commsec 安全通道强制约束不直接作用于客户端进程侧。

## 3. 后续维护规则

- 若客户端认证链路发生调整，优先更新 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`，再同步本文件。
