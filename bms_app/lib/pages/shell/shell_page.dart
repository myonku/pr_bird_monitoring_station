import 'package:flutter/material.dart';

import 'package:bms_app/app/app_controller.dart';
import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/pages/home/home_page.dart';
import 'package:bms_app/pages/me/me_page.dart';
import 'package:bms_app/pages/records/records_page.dart';
import 'package:bms_app/pages/stats/stats_page.dart';

class ShellPage extends StatelessWidget {
  const ShellPage({
    super.key,
    required this.controller,
    required this.monitoringController,
  });

  final AppController controller;
  final MonitoringController monitoringController;

  @override
  Widget build(BuildContext context) {
    final pages = [
      HomePage(
        controller: controller,
        mode: monitoringController.mode,
        monitoringController: monitoringController,
      ),
      RecordsPage(monitoringController: monitoringController),
      StatsPage(monitoringController: monitoringController),
      MePage(monitoringController: monitoringController),
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
                  monitoringController.mode.displayName,
                  style: TextStyle(
                    fontSize: 12,
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
