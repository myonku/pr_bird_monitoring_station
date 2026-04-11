import 'package:flutter/material.dart';

import 'package:bms_app/app/app_controller.dart';
import 'package:bms_app/auth/auth_controller.dart';
import 'package:bms_app/data_source/home_data_source.dart';
import 'package:bms_app/data_source/records_data_source.dart';
import 'package:bms_app/data_source/stats_data_source.dart';
import 'package:bms_app/models/monitoring_models.dart';
import 'package:bms_app/pages/home_page.dart';
import 'package:bms_app/pages/me_page.dart';
import 'package:bms_app/pages/records_page.dart';
import 'package:bms_app/pages/stats_page.dart';

class ShellPage extends StatelessWidget {
  const ShellPage({
    super.key,
    required this.controller,
    required this.authController,
    required this.homeDataSource,
    required this.recordsDataSource,
    required this.statsDataSource,
  });

  final AppController controller;
  final AuthController authController;
  final HomeDataSource homeDataSource;
  final RecordsDataSource recordsDataSource;
  final StatsDataSource statsDataSource;

  @override
  Widget build(BuildContext context) {
    final pages = [
      HomePage(
        controller: controller,
        mode: authController.mode,
        dataSource: homeDataSource,
      ),
      RecordsPage(dataSource: recordsDataSource),
      StatsPage(
        statsDataSource: statsDataSource,
        recordsDataSource: recordsDataSource,
      ),
      MePage(authController: authController),
    ];

    const titles = ['首页', '记录', '统计', '我的'];

    return Scaffold(
      appBar: AppBar(
        title: Text(titles[controller.currentIndex]),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 16),
            child: Center(
              child: Container(
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 6,
                ),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primaryContainer,
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  authController.mode == AppMode.development ? 'DEV' : 'NA',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: Theme.of(context).colorScheme.onPrimaryContainer,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
      body: IndexedStack(index: controller.currentIndex, children: pages),
      bottomNavigationBar: NavigationBar(
        selectedIndex: controller.currentIndex,
        onDestinationSelected: controller.setIndex,
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.dashboard_outlined),
            selectedIcon: Icon(Icons.dashboard),
            label: '首页',
          ),
          NavigationDestination(
            icon: Icon(Icons.list_alt_outlined),
            selectedIcon: Icon(Icons.list_alt),
            label: '记录',
          ),
          NavigationDestination(
            icon: Icon(Icons.bar_chart_outlined),
            selectedIcon: Icon(Icons.bar_chart),
            label: '统计',
          ),
          NavigationDestination(
            icon: Icon(Icons.person_outline),
            selectedIcon: Icon(Icons.person),
            label: '我的',
          ),
        ],
      ),
    );
  }
}
