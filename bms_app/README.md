# bms_app

鸟类监测系统 Flutter 客户端。

## 项目说明

- 客户端页面统一依赖 `MonitoringController`，不再通过旧的 repository / service 链路分发业务逻辑。
- 启动入口在 `lib/main.dart` 里通过 `MonitoringDataSource` 切换 mock 客户端和真实 HTTP 客户端。
- `kServerBaseUrl` 用于配置真实后端地址，仅在 `httpClient` 模式下生效。
- 登录会话会通过 `PersistentAuthSessionStore` 持久化到本地文件，应用重启后无需重新登录。

## 启动配置

- `kMonitoringDataSource = MonitoringDataSource.mockClient` 时，应用走本地 mock 数据，默认不依赖后端。
- `kMonitoringDataSource = MonitoringDataSource.httpClient` 时，应用通过 `HttpMonitoringClient` 请求后端，并使用 `kServerBaseUrl` 作为请求域名。
- 当前默认是 mock 模式；如果要联调真实后端，只需要切换这两个常量。

## 目录说明

- `lib/controller/`：统一业务控制器。
- `lib/transport/`：客户端传输层和 HTTP/mock 实现。
- `lib/storage/`：认证会话存储。
- `lib/pages/`：页面层。

## 运行

```bash
flutter pub get
flutter run
```

## 联调提示

- 登录、刷新会话和用户资料拉取走认证接口。
- 首页、记录页、统计页和我的页面直接调用统一控制器，不再手工拼接页面级数据源。
- 记录页首次进入时会直接拉取数据，避免空白状态。
