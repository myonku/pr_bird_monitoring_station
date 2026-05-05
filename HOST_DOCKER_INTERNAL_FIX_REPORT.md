# Docker host.docker.internal 映射修复报告

## 问题诊断

### 问题描述
机器重启后，Windows hosts 文件中 `host.docker.internal` 的映射被修改为 `172.18.0.1`，导致宿主机应用无法正确连接 Docker 容器中的服务（尤其是 Redis 集群）。

### 根本原因
- **错误的映射**：`host.docker.internal` 被映射到 `172.18.0.1`
- **172.18.0.1 的含义**：这是 Docker 虚拟网络的网关地址，不是宿主机的实际 IP
- **连接失败原因**：
  - Redis 集群通过 `host.docker.internal:7001-7006` 对外公布地址
  - 宿主机应用尝试连接 `host.docker.internal:7001`
  - DNS 解析 `host.docker.internal` 得到 `172.18.0.1`
  - 宿主机应用无法通过 `172.18.0.1:7001` 连接（这是容器网络内的地址，宿主机不可达）

## 修复方案实施

### 1. 更新 Windows hosts 文件

**文件路径**：`C:\Windows\System32\drivers\etc\hosts`

**修改内容**：
```
# 修改前
172.18.0.1 host.docker.internal

# 修改后  
10.160.15.241 host.docker.internal
```

**修改原因**：
- `10.160.15.241` 是宿主机的实际 IP（以太网接口）
- 这样 `host.docker.internal` 就可以正确解析为宿主机地址
- 宿主机应用连接 `host.docker.internal:7001` 时，会正确路由到宿主机的端口映射

**执行方式**：
使用 PowerShell 管理员脚本进行替换（需要管理员权限）

### 2. 恢复 docker-compose.yml 配置

**修改的位置**：所有 6 个 Redis 节点和 redis-cluster-init 配置

**修改内容**：
```yaml
# redis-node-1 到 redis-node-6
redis-server
  ...
  --cluster-announce-ip host.docker.internal  # 恢复为原始值
  --cluster-announce-port 7001
  
# redis-cluster-init
command: >
  sh -c "sleep 5 && echo 'yes' | redis-cli -a 'YourRedisPassword123!' --cluster create \
  host.docker.internal:7001 host.docker.internal:7002 host.docker.internal:7003 \
  host.docker.internal:7004 host.docker.internal:7005 host.docker.internal:7006 \
  --cluster-replicas 1"
```

### 3. 恢复服务配置文件

**certification_server/settings.toml**：
```toml
[mysql]
dsn = "project_user:YourUserPassword123!@tcp(host.docker.internal:3306)/bms_test?charset=utf8mb4&parseTime=true&loc=Local"

[redis]
addrs = "host.docker.internal:7001,host.docker.internal:7002,host.docker.internal:7003,host.docker.internal:7004,host.docker.internal:7005,host.docker.internal:7006"

[etcd]
endpoints = "host.docker.internal:23791,host.docker.internal:23811,host.docker.internal:23813"
```

## 修复验证

### Redis 集群状态
```
cluster_state: ok
cluster_slots_assigned: 16384
cluster_slots_ok: 16384
cluster_known_nodes: 6
cluster_size: 3
```

### 集群节点配置
```
✓ host.docker.internal:7001@17001 master
✓ host.docker.internal:7002@17002 master
✓ host.docker.internal:7003@17003 master
✓ host.docker.internal:7004@17004 slave
✓ host.docker.internal:7005@17005 slave
✓ host.docker.internal:7006@17006 slave
```

## 网络配置参考

### 当前宿主机网络接口
```
主要 IP（以太网）：10.160.15.241
VMware Adapter：192.168.11.1, 192.168.204.1
WSL 虚拟网络：172.28.0.1
回环地址：127.0.0.1
Docker 网络网关：172.18.0.1
```

### Docker 网络配置
```
Network: project-network
Subnet: 172.18.0.0/16
Gateway: 172.18.0.1
```

## 预防措施

为了防止此问题再次发生，建议：

1. **定期检查 hosts 文件映射**
   ```powershell
   Get-Content C:\Windows\System32\drivers\etc\hosts | Select-String "host.docker"
   ```

2. **创建备份脚本**
   - 定期备份 hosts 文件
   - 在修改前保存当前映射

3. **自动化修复脚本**
   ```powershell
   # 检查并自动修复 host.docker.internal 映射
   $hostsFile = "C:\Windows\System32\drivers\etc\hosts"
   $currentIP = Get-NetIPAddress -InterfaceAlias "以太网" -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
   $hosts = Get-Content $hostsFile
   if ($hosts | Select-String "host.docker.internal") {
       $hosts = $hosts -replace "^[\d\.]+\s+host\.docker\.internal", "$currentIP host.docker.internal"
       Set-Content -Path $hostsFile -Value $hosts -Encoding ASCII -Force
   }
   ```

## 修复后的工作流程

```
宿主机应用
    ↓
连接 host.docker.internal:7001
    ↓
DNS 解析 → 10.160.15.241:7001
    ↓
宿主机网络 → Docker port mapping
    ↓
容器网络 172.18.0.0/16
    ↓
Redis 容器接收连接 (172.18.0.x:6379)
```

## 相关文档
- Docker Compose 文件：`docker-compose.yml`
- 服务配置文件：各模块的 `settings.toml`
- Redis 集群文档：请参考 Redis 官方文档关于 cluster-announce-ip 的说明

---
**修复日期**：2026-05-05
**修复状态**：✅ 完成并验证
