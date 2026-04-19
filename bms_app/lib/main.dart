import 'package:flutter/material.dart';

import 'package:bms_app/app/bms_app.dart';
import 'package:bms_app/models/common.dart';

const AppMode kInitialAppMode = AppMode.noAuth;

void main() {
  runApp(const BirdMonitoringApp(initialMode: kInitialAppMode));
}
