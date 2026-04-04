# 客户端认证说明（索引版）

状态：索引文档

## 1. 说明

- 客户端认证链路与启动链路已统一归口到 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`（第 6 章）。
- 全局约定（UUID、密钥、配置生命周期）见 `SYSTEM_GLOBAL_BASELINE_DESIGN.md`。
- 边缘端认证与上传接口契约见 `edge_server/EDGE_GATEWAY_CHANNEL_INTERFACE_CONTRACT.md`。

## 2. 客户端边界（保留）

- 客户端不参与本地密钥 bootstrap。
- 客户端仅通过网关进行登录、续期、校验、登出相关请求。
- 用户实体 ID 仅由后端认证结果返回。

## 3. 后续维护规则

- 若客户端认证链路发生调整，优先更新 `SYSTEM_AUTH_STARTUP_CHAIN_DESIGN.md`，再同步本文件。
