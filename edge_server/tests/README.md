# Edge Server 认证测试套件

本目录包含edge_server bootstrap和token refresh认证流程的测试脚本。

## 文件说明

### test_bootstrap_auth_flow.py
完整的edge_server认证流程测试，包括：
1. Bootstrap challenge请求
2. 使用edge_server私钥签名challenge
3. 提交签名proof进行认证
4. Token refresh流程测试

**运行方式**:
```bash
cd edge_server
.\.venv\Scripts\python.exe tests/test_bootstrap_auth_flow.py
```

### debug_bootstrap.py
单步调试脚本，用于问题排查和观察中间步骤。展示：
- Challenge response格式
- 签名载荷构建过程
- Proof提交和响应

**运行方式**:
```bash
cd edge_server
.\.venv\Scripts\python.exe tests/debug_bootstrap.py
```

### TEST_RESULTS.md
完整的测试报告，包括：
- 测试环境配置
- 逐步测试流程和结果
- API请求/响应示例
- 关键发现和修复说明

## 前置条件

1. **证书认证中心启动**:
   ```bash
   cd certification_server
   go run main.go
   ```

2. **网关启动**:
   ```bash
   cd gateway
   go run main.go
   ```

3. **Edge Server虚拟环境**:
   ```bash
   cd edge_server
   # 虚拟环境已在.venv中，直接使用
   .\.venv\Scripts\python.exe -m pip install -e .
   ```

4. **Docker环境** (MySQL, Redis, etcd):
   - 通过docker-compose.yml启动
   - 地址: host.docker.internal:3306, 127.0.0.1:7001-7006, 127.0.0.1:23791-23813

## 时间精度修复验证

该测试重点验证了edge_server的bootstrap时间戳精度修复：

✓ **修复内容**: `src/utils/crypto_utils.py::unix_ts_to_rfc3339nano`
- 从直接计算改为毫秒恢复算法
- 避免IEEE 754浮点精度丢失
- 确保RFC3339Nano格式与认证中心验签一致

✓ **验证方式**: 
- 完整的bootstrap→authenticate→refresh认证流程
- 网关转发到认证中心的签名验证通过
- Tokens正确返回和刷新

## 观察结果

1. Gateway API合约使用嵌套格式：`{challenge: {...}, signed: {...}}`
2. Gateway返回毫秒时间戳（`*_ms`），需转换为秒供edge处理
3. RFC3339Nano格式转换正确，精度问题已解决
4. 完整的认证流程跨越：Device → Gateway → Certification Server → Gateway → Device

## 故障排查

如果遇到`challenge_id is required`错误：
- 检查请求格式是否包含完整的challenge对象和signed对象
- 验证challenge_id是否正确传递（不能为空或null）
- 运行debug_bootstrap.py观察中间步骤

## 相关文档

- [edge_server/EDGE_AUTH_DESIGN_SPEC.md](../EDGE_AUTH_DESIGN_SPEC.md) - 边缘端认证设计
- [gateway_bootstrap_time_precision_fix.md](/memories/repo/gateway_bootstrap_time_precision_fix.md) - 时间精度修复记录
