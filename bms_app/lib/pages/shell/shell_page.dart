import 'package:flutter/material.dart';

import 'package:bms_app/app/app_controller.dart';
import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/models/common.dart';
import 'package:bms_app/pages/home/home_page.dart';
import 'package:bms_app/pages/me/me_page.dart';
import 'package:bms_app/pages/records/records_page.dart';
import 'package:bms_app/pages/stats/stats_page.dart';

class ShellPage extends StatefulWidget {
  const ShellPage({
    super.key,
    required this.controller,
    required this.monitoringController,
  });

  final AppController controller;
  final MonitoringController monitoringController;

  @override
  State<ShellPage> createState() => _ShellPageState();
}

class _ShellPageState extends State<ShellPage> {
  final List<Widget?> _pages = List<Widget?>.filled(4, null);

  static const List<String> _titles = ['首页', '记录', '统计', '我的'];

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onIndexChanged);
    // Ensure initial page is created (usually index 0)
    _ensurePage(widget.controller.currentIndex);
  }

  @override
  void didUpdateWidget(covariant ShellPage oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller.removeListener(_onIndexChanged);
      widget.controller.addListener(_onIndexChanged);
    }
  }

  @override
  void dispose() {
    widget.controller.removeListener(_onIndexChanged);
    super.dispose();
  }

  void _onIndexChanged() {
    final idx = widget.controller.currentIndex;
    _ensurePage(idx);
    setState(() {});
  }

  void _ensurePage(int index) {
    if (_pages[index] != null) return;

    switch (index) {
      case 0:
        _pages[0] = HomePage(
          controller: widget.controller,
          mode: widget.monitoringController.mode,
          monitoringController: widget.monitoringController,
        );
        break;
      case 1:
        _pages[1] = RecordsPage(monitoringController: widget.monitoringController);
        break;
      case 2:
        _pages[2] = StatsPage(monitoringController: widget.monitoringController);
        break;
      case 3:
        _pages[3] = MePage(monitoringController: widget.monitoringController);
        break;
      default:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    final currentIndex = widget.controller.currentIndex;

    return Scaffold(
      appBar: AppBar(
        title: Text(_titles[currentIndex]),
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
                  widget.monitoringController.mode.displayName,
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
      body: IndexedStack(
        index: currentIndex,
        children: List<Widget>.generate(
          4,
          (i) => _pages[i] ?? const SizedBox.shrink(),
        ),
      ),
      bottomNavigationBar: NavigationBar(
        selectedIndex: currentIndex,
        onDestinationSelected: widget.controller.setIndex,
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
