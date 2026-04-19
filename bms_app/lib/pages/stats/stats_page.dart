import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'package:bms_app/data_source/monitoring_repository.dart';
import 'package:bms_app/models/common.dart';

class StatsPage extends StatefulWidget {
  const StatsPage({
    super.key,
    required this.repository,
  });

  final MonitoringRepository repository;

  @override
  State<StatsPage> createState() => _StatsPageState();
}

class _StatsPageState extends State<StatsPage> {
  static const int _maxSelectableRangeDays = 30;

  Future<List<TrendPoint>>? _weeklyTrendFuture;
  String _selectedStationId = '';
  DateTimeRange? _selectedRange;
  bool _isLoading = true;
  String? _errorMessage;
  List<RecordStationOption> _stations = const [
    RecordStationOption(deviceId: '', deviceName: '全部站点'),
  ];
  List<BirdRecord> _rangeRecords = const [];

  @override
  void initState() {
    super.initState();
    final today = DateUtils.dateOnly(DateTime.now());
    _selectedRange = DateTimeRange(
      start: today.subtract(const Duration(days: 6)),
      end: today,
    );
    _weeklyTrendFuture = _loadWeeklyTrend();
    _bootstrap();
  }

  Future<List<TrendPoint>> _loadWeeklyTrend() {
    return widget.repository.fetchWeeklyTrend(days: 7);
  }

  Future<void> _bootstrap() async {
    try {
      final stations = await widget.repository.fetchStationOptions();
      if (!mounted) {
        return;
      }
      setState(() {
        _stations = [
          const RecordStationOption(deviceId: '', deviceName: '全部站点'),
          ...stations,
        ];
      });
      await _reloadRangeRecords();
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _errorMessage = '站点列表加载失败：$error';
        _isLoading = false;
      });
    }
  }

  Future<void> _reloadRangeRecords() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final records = await widget.repository.fetchRecords(
        dateRange: _selectedRange,
        stationId: _selectedStationId.isEmpty ? null : _selectedStationId,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _rangeRecords = records;
        _isLoading = false;
      });
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _errorMessage = '统计数据加载失败：$error';
        _isLoading = false;
      });
    }
  }

  Future<void> _pickDateRange() async {
    final today = DateUtils.dateOnly(DateTime.now());
    final result = await showDateRangePicker(
      context: context,
      firstDate: today.subtract(const Duration(days: 365)),
      lastDate: today,
      initialDateRange: _selectedRange,
      helpText: '选择统计时间段',
    );
    if (result == null) {
      return;
    }

    final start = DateUtils.dateOnly(result.start);
    final end = DateUtils.dateOnly(result.end);
    final dayCount = end.difference(start).inDays + 1;
    if (dayCount > _maxSelectableRangeDays) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('时间段最长 30 天')));
      return;
    }

    setState(() {
      _selectedRange = DateTimeRange(start: start, end: end);
    });
    await _reloadRangeRecords();
  }

  void _changeStation(String? value) {
    if (value == null || value == _selectedStationId) {
      return;
    }

    setState(() {
      _selectedStationId = value;
    });
    _reloadRangeRecords();
  }

  String get _selectedRangeLabel {
    if (_selectedRange == null) {
      return '全部日期';
    }

    final start = _selectedRange!.start;
    final end = _selectedRange!.end;
    return '${start.year}-${start.month.toString().padLeft(2, '0')}-${start.day.toString().padLeft(2, '0')} 至 ${end.year}-${end.month.toString().padLeft(2, '0')}-${end.day.toString().padLeft(2, '0')}';
  }

  int get _selectedRangeDays {
    if (_selectedRange == null) {
      return 0;
    }
    final start = DateUtils.dateOnly(_selectedRange!.start);
    final end = DateUtils.dateOnly(_selectedRange!.end);
    return end.difference(start).inDays + 1;
  }

  List<TrendPoint> get _dailyDistribution {
    if (_selectedRange == null) {
      return const [];
    }

    final start = DateUtils.dateOnly(_selectedRange!.start);
    final end = DateUtils.dateOnly(_selectedRange!.end);
    final countsByDay = <DateTime, int>{};
    for (final record in _rangeRecords) {
      final day = DateUtils.dateOnly(record.capturedAtTime);
      countsByDay[day] = (countsByDay[day] ?? 0) + 1;
    }

    final points = <TrendPoint>[];
    for (
      var day = start;
      !day.isAfter(end);
      day = day.add(const Duration(days: 1))
    ) {
      points.add(
        TrendPoint(
          label: '${day.month}/${day.day}',
          value: countsByDay[day] ?? 0,
        ),
      );
    }
    return points;
  }

  List<SpeciesShare> get _speciesShares {
    if (_rangeRecords.isEmpty) {
      return const [];
    }

    final countsBySpecies = <String, int>{};
    final colorBySpecies = <String, Color>{};
    for (final record in _rangeRecords) {
      countsBySpecies[record.species] =
          (countsBySpecies[record.species] ?? 0) + 1;
      colorBySpecies.putIfAbsent(record.species, () => record.accent);
    }

    final entries = countsBySpecies.entries.toList()
      ..sort((left, right) => right.value.compareTo(left.value));

    return entries
        .map(
          (entry) => SpeciesShare(
            label: entry.key,
            value: entry.value,
            color: colorBySpecies[entry.key] ?? const Color(0xFF0B7A75),
          ),
        )
        .toList();
  }

  @override
  Widget build(BuildContext context) {
    final dailyDistribution = _dailyDistribution;
    final speciesShares = _speciesShares;

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        Text('最近一周趋势', style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 12),
        FutureBuilder<List<TrendPoint>>(
          future: _weeklyTrendFuture,
          builder: (context, snapshot) {
            if (snapshot.connectionState == ConnectionState.waiting) {
              return const _LoadingPanel();
            }
            if (snapshot.hasError) {
              return _MessagePanel(
                icon: Icons.error_outline,
                title: '趋势数据加载失败',
                description: '${snapshot.error}',
              );
            }
            return _WeeklyTrendCard(points: snapshot.data ?? const []);
          },
        ),
        const SizedBox(height: 18),
        Text('时间段查询', style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 12),
        _StatsQueryPanel(
          stations: _stations,
          selectedStationId: _selectedStationId,
          selectedRangeLabel: _selectedRangeLabel,
          selectedRangeDays: _selectedRangeDays,
          onSelectRange: _isLoading ? null : _pickDateRange,
          onStationChanged: _isLoading ? null : _changeStation,
        ),
        const SizedBox(height: 18),
        Text('所选时间段识别数量分布', style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 10),
        if (_errorMessage != null)
          _MessagePanel(
            icon: Icons.error_outline,
            title: '数据加载失败',
            description: _errorMessage!,
          )
        else if (_isLoading)
          const _LoadingPanel()
        else if (dailyDistribution.isEmpty)
          const _MessagePanel(
            icon: Icons.search_off,
            title: '暂无识别记录',
            description: '所选时间段和站点下没有查询到记录。',
          )
        else
          _DailyDistributionCard(points: dailyDistribution),
        const SizedBox(height: 18),
        Text('物种占比', style: Theme.of(context).textTheme.titleLarge),
        const SizedBox(height: 10),
        if (_errorMessage != null)
          _MessagePanel(
            icon: Icons.error_outline,
            title: '数据加载失败',
            description: _errorMessage!,
          )
        else if (_isLoading)
          const _LoadingPanel()
        else if (speciesShares.isEmpty)
          const _MessagePanel(
            icon: Icons.flutter_dash,
            title: '暂无物种分布',
            description: '所选时间段和站点下没有可统计的物种数据。',
          )
        else
          _SpeciesShareCard(shares: speciesShares),
        const SizedBox(height: 18),
        const _StatsNoteCard(),
      ],
    );
  }
}

class _StatsQueryPanel extends StatelessWidget {
  const _StatsQueryPanel({
    required this.stations,
    required this.selectedStationId,
    required this.selectedRangeLabel,
    required this.selectedRangeDays,
    required this.onSelectRange,
    required this.onStationChanged,
  });

  final List<RecordStationOption> stations;
  final String selectedStationId;
  final String selectedRangeLabel;
  final int selectedRangeDays;
  final VoidCallback? onSelectRange;
  final ValueChanged<String?>? onStationChanged;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  '查询条件',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ),
              TextButton.icon(
                onPressed: onSelectRange,
                icon: const Icon(Icons.date_range_outlined),
                label: const Text('选择时间段'),
              ),
            ],
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            initialValue: selectedStationId,
            decoration: const InputDecoration(
              labelText: '站点',
              prefixIcon: Icon(Icons.place_outlined),
            ),
            items: stations
                .map(
                  (station) => DropdownMenuItem(
                    value: station.deviceId,
                    child: Text(station.deviceName),
                  ),
                )
                .toList(),
            onChanged: onStationChanged,
          ),
          const SizedBox(height: 12),
          Text(
            '当前时间段：$selectedRangeLabel',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 4),
          Text(
            '当前区间 $selectedRangeDays 天，最长支持 30 天。',
            style: Theme.of(
              context,
            ).textTheme.bodySmall?.copyWith(color: Colors.black54),
          ),
        ],
      ),
    );
  }
}

class _WeeklyTrendCard extends StatelessWidget {
  const _WeeklyTrendCard({required this.points});

  final List<TrendPoint> points;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                child: Icon(
                  Icons.show_chart,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  '最近七日识别趋势',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          _WeeklyTrendChart(points: points),
        ],
      ),
    );
  }
}

class _WeeklyTrendChart extends StatelessWidget {
  const _WeeklyTrendChart({required this.points});

  final List<TrendPoint> points;

  @override
  Widget build(BuildContext context) {
    if (points.isEmpty) {
      return const _MessagePanel(
        icon: Icons.bar_chart_outlined,
        title: '暂无趋势数据',
        description: '当前没有可展示的最近一周趋势。',
      );
    }

    return Column(
      children: [
        LayoutBuilder(
          builder: (context, constraints) {
            return SizedBox(
              width: constraints.maxWidth,
              height: 180,
              child: CustomPaint(
                painter: _WeeklyTrendPainter(
                  points: points,
                  lineColor: Theme.of(context).colorScheme.primary,
                  fillColor: Theme.of(
                    context,
                  ).colorScheme.primaryContainer.withValues(alpha: 0.65),
                  gridColor: Theme.of(
                    context,
                  ).colorScheme.outlineVariant.withValues(alpha: 0.55),
                ),
              ),
            );
          },
        ),
        const SizedBox(height: 12),
        Row(
          children: points
              .map(
                (point) => Expanded(
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 2),
                    child: Text(
                      point.label,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ),
                ),
              )
              .toList(),
        ),
      ],
    );
  }
}

class _WeeklyTrendPainter extends CustomPainter {
  _WeeklyTrendPainter({
    required this.points,
    required this.lineColor,
    required this.fillColor,
    required this.gridColor,
  });

  final List<TrendPoint> points;
  final Color lineColor;
  final Color fillColor;
  final Color gridColor;

  @override
  void paint(Canvas canvas, Size size) {
    if (points.isEmpty) {
      return;
    }

    const padding = EdgeInsets.fromLTRB(20, 14, 16, 26);
    final plotLeft = padding.left;
    final plotTop = padding.top;
    final plotWidth = size.width - padding.left - padding.right;
    final plotHeight = size.height - padding.top - padding.bottom;
    if (plotWidth <= 0 || plotHeight <= 0) {
      return;
    }

    final maxValue = points.map((point) => point.value).reduce(math.max);
    final minValue = points.map((point) => point.value).reduce(math.min);
    final range = math.max(1, maxValue - minValue);

    final gridPaint = Paint()
      ..color = gridColor
      ..strokeWidth = 1;

    for (var index = 0; index < 4; index++) {
      final y = plotTop + plotHeight * index / 3;
      canvas.drawLine(
        Offset(plotLeft, y),
        Offset(plotLeft + plotWidth, y),
        gridPaint,
      );
    }

    final linePoints = <Offset>[];
    for (var index = 0; index < points.length; index++) {
      final point = points[index];
      final x = points.length == 1
          ? plotLeft + plotWidth / 2
          : plotLeft + plotWidth * index / (points.length - 1);
      final normalized = (point.value - minValue) / range;
      final y = plotTop + plotHeight * (1 - normalized);
      linePoints.add(Offset(x, y));
    }

    final linePath = Path()..moveTo(linePoints.first.dx, linePoints.first.dy);
    for (var index = 1; index < linePoints.length; index++) {
      linePath.lineTo(linePoints[index].dx, linePoints[index].dy);
    }

    final fillPath = Path.from(linePath)
      ..lineTo(linePoints.last.dx, plotTop + plotHeight)
      ..lineTo(linePoints.first.dx, plotTop + plotHeight)
      ..close();

    final fillPaint = Paint()
      ..shader = LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [fillColor, fillColor.withValues(alpha: 0.0)],
      ).createShader(Rect.fromLTWH(plotLeft, plotTop, plotWidth, plotHeight));

    final linePaint = Paint()
      ..color = lineColor
      ..strokeWidth = 3
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;

    canvas.drawPath(fillPath, fillPaint);
    canvas.drawPath(linePath, linePaint);

    final dotFillPaint = Paint()..color = Colors.white;
    final dotBorderPaint = Paint()
      ..color = lineColor
      ..strokeWidth = 2.2
      ..style = PaintingStyle.stroke;

    for (final offset in linePoints) {
      canvas.drawCircle(offset, 5, dotFillPaint);
      canvas.drawCircle(offset, 5, dotBorderPaint);
    }
  }

  @override
  bool shouldRepaint(covariant _WeeklyTrendPainter oldDelegate) {
    return oldDelegate.points != points ||
        oldDelegate.lineColor != lineColor ||
        oldDelegate.fillColor != fillColor ||
        oldDelegate.gridColor != gridColor;
  }
}

class _DailyDistributionCard extends StatelessWidget {
  const _DailyDistributionCard({required this.points});

  final List<TrendPoint> points;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                child: Icon(
                  Icons.bar_chart,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  '识别数量分布',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Text(
            '横坐标会根据所选时间段自动展开，适合不同长度的区间。',
            style: Theme.of(
              context,
            ).textTheme.bodySmall?.copyWith(color: Colors.black54),
          ),
          const SizedBox(height: 16),
          LayoutBuilder(
            builder: (context, constraints) {
              final chartWidth = math.max(
                constraints.maxWidth,
                points.length * 52.0,
              );
              final maxValue = points
                  .map((point) => point.value)
                  .fold<int>(
                    0,
                    (current, next) => current > next ? current : next,
                  );

              return SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: SizedBox(
                  width: chartWidth,
                  child: Column(
                    children: [
                      SizedBox(
                        height: 190,
                        child: Stack(
                          children: [
                            Positioned.fill(
                              child: CustomPaint(
                                painter: _BarGridPainter(
                                  gridColor: Theme.of(context)
                                      .colorScheme
                                      .outlineVariant
                                      .withValues(alpha: 0.55),
                                ),
                              ),
                            ),
                            Align(
                              alignment: Alignment.bottomCenter,
                              child: Row(
                                crossAxisAlignment: CrossAxisAlignment.end,
                                children: points.map((point) {
                                  final ratio = maxValue == 0
                                      ? 0.0
                                      : point.value / maxValue;
                                  final barHeight = 12 + (124 * ratio);
                                  return SizedBox(
                                    width: 52,
                                    child: Column(
                                      mainAxisAlignment: MainAxisAlignment.end,
                                      children: [
                                        Text(
                                          '${point.value}',
                                          style: Theme.of(
                                            context,
                                          ).textTheme.bodySmall,
                                        ),
                                        const SizedBox(height: 8),
                                        Container(
                                          width: 18,
                                          height: barHeight,
                                          decoration: BoxDecoration(
                                            borderRadius: BorderRadius.circular(
                                              10,
                                            ),
                                            gradient: LinearGradient(
                                              begin: Alignment.topCenter,
                                              end: Alignment.bottomCenter,
                                              colors: [
                                                Theme.of(
                                                  context,
                                                ).colorScheme.primary,
                                                Theme.of(context)
                                                    .colorScheme
                                                    .primary
                                                    .withValues(alpha: 0.55),
                                              ],
                                            ),
                                          ),
                                        ),
                                      ],
                                    ),
                                  );
                                }).toList(),
                              ),
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 12),
                      Row(
                        children: points.map((point) {
                          return SizedBox(
                            width: 52,
                            child: Padding(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 2,
                              ),
                              child: Text(
                                point.label,
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                                textAlign: TextAlign.center,
                                style: Theme.of(context).textTheme.bodySmall,
                              ),
                            ),
                          );
                        }).toList(),
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
        ],
      ),
    );
  }
}

class _BarGridPainter extends CustomPainter {
  _BarGridPainter({required this.gridColor});

  final Color gridColor;

  @override
  void paint(Canvas canvas, Size size) {
    final gridPaint = Paint()
      ..color = gridColor
      ..strokeWidth = 1;

    for (var index = 0; index < 4; index++) {
      final y = size.height * index / 3;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }
  }

  @override
  bool shouldRepaint(covariant _BarGridPainter oldDelegate) {
    return oldDelegate.gridColor != gridColor;
  }
}

class _SpeciesShareCard extends StatelessWidget {
  const _SpeciesShareCard({required this.shares});

  final List<SpeciesShare> shares;

  @override
  Widget build(BuildContext context) {
    final total = shares.fold<int>(
      0,
      (current, share) => current + share.value,
    );

    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Column(
        children: [
          ...shares.map((share) {
            final percent = total == 0
                ? 0
                : (share.value / total * 100).round();
            return Padding(
              padding: const EdgeInsets.only(bottom: 14),
              child: Row(
                children: [
                  Container(
                    width: 12,
                    height: 12,
                    decoration: BoxDecoration(
                      color: share.color,
                      shape: BoxShape.circle,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(child: Text(share.label)),
                  Text('${share.value} 条'),
                  const SizedBox(width: 10),
                  Text('$percent%'),
                ],
              ),
            );
          }),
          const SizedBox(height: 8),
          Container(
            height: 18,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(999),
              color: const Color(0xFFE9EEF5),
            ),
            clipBehavior: Clip.antiAlias,
            child: Row(
              children: shares.map((share) {
                return Expanded(
                  flex: math.max(share.value, 1),
                  child: Container(color: share.color),
                );
              }).toList(),
            ),
          ),
        ],
      ),
    );
  }
}

class _LoadingPanel extends StatelessWidget {
  const _LoadingPanel();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 36),
      alignment: Alignment.center,
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: const CircularProgressIndicator(),
    );
  }
}

class _MessagePanel extends StatelessWidget {
  const _MessagePanel({
    required this.icon,
    required this.title,
    required this.description,
  });

  final IconData icon;
  final String title;
  final String description;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CircleAvatar(
            backgroundColor: Theme.of(context).colorScheme.primaryContainer,
            child: Icon(icon, color: Theme.of(context).colorScheme.primary),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(
                  description,
                  style: Theme.of(
                    context,
                  ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _StatsNoteCard extends StatelessWidget {
  const _StatsNoteCard();

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(24),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          CircleAvatar(
            backgroundColor: Theme.of(context).colorScheme.primaryContainer,
            child: Icon(
              Icons.analytics_outlined,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('统计说明', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(
                  '顶部折线图固定展示最近一周趋势；底部两张图会跟随所选时间段和站点实时刷新，时间段最长 30 天。',
                  style: Theme.of(
                    context,
                  ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
