import 'package:bms_app/transport/builder.dart';
import 'package:flutter/material.dart';

import 'package:bms_app/app/bms_app.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/storage/auth_stores.dart';

// 表示运行模式，决定是否启用认证功能
const AppMode kInitialAppMode = AppMode.noAuth;

// 监测数据来源，决定使用真实 HTTP 客户端还是模拟客户端
const MonitoringDataSource kMonitoringDataSource = MonitoringDataSource.mockClient;

// 服务器基础 URL，仅在使用 HTTP 客户端时有效
const String kServerBaseUrl = 'http://127.0.0.1:8080';


void main() {
  final client = buildMonitoringClient(kMonitoringDataSource, kServerBaseUrl);
  final sessionStore = PersistentAuthSessionStore();
  runApp(
    BirdMonitoringApp(
      client: client,
      sessionStore: sessionStore,
      initialMode: kInitialAppMode,
    ),
  );
}
