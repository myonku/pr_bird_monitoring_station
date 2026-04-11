import 'package:flutter/material.dart';

import 'package:bms_app/data_source/records_data_source.dart';
import 'package:bms_app/models/monitoring_models.dart';
import 'package:bms_app/pages/record_detail_page.dart';

class RecordsPage extends StatefulWidget {
  const RecordsPage({super.key, required this.dataSource});

  final RecordsDataSource dataSource;

  @override
  State<RecordsPage> createState() => _RecordsPageState();
}

class _RecordsPageState extends State<RecordsPage> {
  String _query = '';
  double _minConfidence = 0.0;
  String _selectedStation = '全部站点';
  DateTimeRange? _selectedRange;
  bool _isLoading = true;
  String? _errorMessage;
  List<String> _stations = const ['全部站点'];
  List<BirdRecord> _backendRecords = const [];

  @override
  void initState() {
    super.initState();
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    try {
      final stations = await widget.dataSource.fetchStationOptions();
      if (!mounted) {
        return;
      }
      setState(() {
        _stations = ['全部站点', ...stations];
      });
      await _reloadRecords();
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

  Future<void> _reloadRecords() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final records = await widget.dataSource.fetchRecords(
        dateRange: _selectedRange,
        stationName: _selectedStation == '全部站点' ? null : _selectedStation,
      );
      if (!mounted) {
        return;
      }
      setState(() {
        _backendRecords = records;
        _isLoading = false;
      });
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _errorMessage = '记录查询失败：$error';
        _isLoading = false;
      });
    }
  }

  List<BirdRecord> get _filteredRecords {
    return _backendRecords.where((record) {
      if (record.confidence < _minConfidence) {
        return false;
      }

      if (_query.isEmpty) {
        return true;
      }

      final lowerQuery = _query.toLowerCase();
      return record.species.toLowerCase().contains(lowerQuery) ||
          record.scientificName.toLowerCase().contains(lowerQuery) ||
          record.stationName.toLowerCase().contains(lowerQuery) ||
          record.capturedAt.toLowerCase().contains(lowerQuery) ||
          record.uploadSummary.toLowerCase().contains(lowerQuery);
    }).toList();
  }

  String get _dateRangeLabel {
    if (_selectedRange == null) {
      return '全部日期';
    }
    final start = _selectedRange!.start;
    final end = _selectedRange!.end;
    return '${start.year}/${start.month}/${start.day} - ${end.year}/${end.month}/${end.day}';
  }

  Future<void> _pickDateRange() async {
    final now = DateTime.now();
    final result = await showDateRangePicker(
      context: context,
      firstDate: DateTime(now.year - 1),
      lastDate: DateTime(now.year + 1),
      initialDateRange: _selectedRange,
      helpText: '选择查询日期范围',
    );
    if (result == null) {
      return;
    }
    setState(() {
      _selectedRange = result;
    });
    await _reloadRecords();
  }

  @override
  Widget build(BuildContext context) {
    final records = _filteredRecords;

    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        _RecordsHeader(totalCount: widget.dataSource.totalRecordCount),
        const SizedBox(height: 16),
        TextField(
          decoration: const InputDecoration(
            hintText: '模糊搜索物种、学名、站点或时间',
            prefixIcon: Icon(Icons.search),
          ),
          onChanged: (value) => setState(() => _query = value.trim()),
        ),
        const SizedBox(height: 14),
        Container(
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
                    onPressed: _isLoading ? null : _pickDateRange,
                    icon: const Icon(Icons.date_range_outlined),
                    label: const Text('选择日期'),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              DropdownButtonFormField<String>(
                initialValue: _selectedStation,
                decoration: const InputDecoration(
                  labelText: '站点',
                  prefixIcon: Icon(Icons.place_outlined),
                ),
                items: _stations
                    .map(
                      (station) => DropdownMenuItem(
                        value: station,
                        child: Text(station),
                      ),
                    )
                    .toList(),
                onChanged: _isLoading
                    ? null
                    : (value) async {
                        if (value == null) {
                          return;
                        }
                        setState(() => _selectedStation = value);
                        await _reloadRecords();
                      },
              ),
              const SizedBox(height: 12),
              Text(
                '日期范围：$_dateRangeLabel',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 6),
              Text(
                '站点列表与日期范围通过后端接口查询；置信度与模糊搜索仅在客户端本地过滤。',
                style: Theme.of(
                  context,
                ).textTheme.bodySmall?.copyWith(color: Colors.black54),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        Text('置信度筛选', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        Wrap(
          spacing: 10,
          runSpacing: 10,
          children: [
            _ConfidenceChip(
              label: '全部',
              selected: _minConfidence == 0,
              onSelected: () => setState(() => _minConfidence = 0),
            ),
            _ConfidenceChip(
              label: '≥90%',
              selected: _minConfidence == 0.9,
              onSelected: () => setState(() => _minConfidence = 0.9),
            ),
            _ConfidenceChip(
              label: '≥95%',
              selected: _minConfidence == 0.95,
              onSelected: () => setState(() => _minConfidence = 0.95),
            ),
            _ConfidenceChip(
              label: '≥98%',
              selected: _minConfidence == 0.98,
              onSelected: () => setState(() => _minConfidence = 0.98),
            ),
          ],
        ),
        const SizedBox(height: 18),
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('识别记录', style: Theme.of(context).textTheme.titleLarge),
            if (!_isLoading)
              Text(
                '${records.length} 条',
                style: Theme.of(
                  context,
                ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
              ),
          ],
        ),
        const SizedBox(height: 12),
        if (_errorMessage != null)
          _ErrorState(message: _errorMessage!, onRetry: _reloadRecords)
        else if (_isLoading)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 48),
            child: Center(child: CircularProgressIndicator()),
          )
        else if (records.isEmpty)
          const _EmptyState()
        else
          ...records.map(
            (record) => Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: _RecordCard(
                record: record,
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (_) => RecordDetailPage(record: record),
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}

class _ConfidenceChip extends StatelessWidget {
  const _ConfidenceChip({
    required this.label,
    required this.selected,
    required this.onSelected,
  });

  final String label;
  final bool selected;
  final VoidCallback onSelected;

  @override
  Widget build(BuildContext context) {
    return ChoiceChip(
      label: Text(label),
      selected: selected,
      onSelected: (_) => onSelected(),
      selectedColor: Theme.of(context).colorScheme.primaryContainer,
    );
  }
}

class _ErrorState extends StatelessWidget {
  const _ErrorState({required this.message, required this.onRetry});

  final String message;
  final Future<void> Function() onRetry;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 40),
      child: Column(
        children: [
          Icon(Icons.error_outline, size: 56, color: Colors.red.shade300),
          const SizedBox(height: 12),
          Text(message, textAlign: TextAlign.center),
          const SizedBox(height: 12),
          FilledButton(onPressed: onRetry, child: const Text('重试')),
        ],
      ),
    );
  }
}

class _RecordsHeader extends StatelessWidget {
  const _RecordsHeader({required this.totalCount});

  final int totalCount;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(24),
        gradient: LinearGradient(
          colors: [
            Theme.of(context).colorScheme.primaryContainer,
            Theme.of(context).colorScheme.secondaryContainer,
          ],
        ),
      ),
      child: Row(
        children: [
          CircleAvatar(
            backgroundColor: Colors.white.withValues(alpha: 0.24),
            child: Icon(
              Icons.data_usage,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('自动上传记录', style: Theme.of(context).textTheme.titleMedium),
                const SizedBox(height: 4),
                Text(
                  '当前共 $totalCount 条记录，边缘设备拍摄、推理并上传，客户端提供统计查询与记录检索。',
                  style: Theme.of(
                    context,
                  ).textTheme.bodySmall?.copyWith(color: Colors.black54),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(top: 60),
      child: Column(
        children: [
          Icon(Icons.search_off, size: 56, color: Colors.grey.shade500),
          const SizedBox(height: 12),
          Text('没有找到匹配记录', style: Theme.of(context).textTheme.titleMedium),
        ],
      ),
    );
  }
}

class _RecordCard extends StatelessWidget {
  const _RecordCard({required this.record, required this.onTap});

  final BirdRecord record;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.white,
      borderRadius: BorderRadius.circular(24),
      child: InkWell(
        borderRadius: BorderRadius.circular(24),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 74,
                height: 74,
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(18),
                  gradient: LinearGradient(
                    colors: [
                      record.accent.withValues(alpha: 0.95),
                      record.accent.withValues(alpha: 0.55),
                    ],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: const Icon(
                  Icons.image_outlined,
                  color: Colors.white,
                  size: 32,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Expanded(
                          child: Text(
                            record.species,
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                        ),
                        Text(
                          '${(record.confidence * 100).toStringAsFixed(0)}%',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    Text(
                      record.scientificName,
                      style: Theme.of(
                        context,
                      ).textTheme.bodySmall?.copyWith(color: Colors.black45),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      record.stationName,
                      style: Theme.of(
                        context,
                      ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      record.capturedAt,
                      style: Theme.of(
                        context,
                      ).textTheme.bodySmall?.copyWith(color: Colors.black45),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
