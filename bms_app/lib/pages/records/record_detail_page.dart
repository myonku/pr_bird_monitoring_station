import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import 'package:bms_app/models/common.dart';

class RecordDetailPage extends StatelessWidget {
  const RecordDetailPage({super.key, required this.record});

  final BirdRecord record;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('记录详情')),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          Container(
            height: 220,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(28),
              gradient: LinearGradient(
                colors: [
                  record.accent.withValues(alpha: 0.95),
                  record.accent.withValues(alpha: 0.55),
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
            ),
            clipBehavior: Clip.antiAlias,
            child: _buildImage(record.imageB64),
          ),
          const SizedBox(height: 20),
          Text(
            record.species,
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 8),
          Text(
            record.scientificName,
            style: Theme.of(
              context,
            ).textTheme.bodyLarge?.copyWith(color: Colors.black54),
          ),
          const SizedBox(height: 10),
          Text(
            '记录为设备自动上传，不包含人工补录描述。简介内容来自资料库，仅用于展示和科普说明。',
            style: Theme.of(
              context,
            ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
          ),
          const SizedBox(height: 20),
          _DetailRow(label: '识别时间', value: record.capturedAt),
          _DetailRow(label: '所属站点', value: record.stationName),
          _DetailRow(
            label: '置信度',
            value: '${(record.confidence * 100).toStringAsFixed(1)}%',
          ),
          _DetailRow(
            label: '环境温度',
            value: '${record.temperature.toStringAsFixed(1)} °C',
          ),
          _DetailRow(label: '环境湿度', value: '${record.humidity}%'),
          const SizedBox(height: 8),
          Container(
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
                      backgroundColor: Theme.of(
                        context,
                      ).colorScheme.primaryContainer,
                      child: Icon(
                        Icons.menu_book_outlined,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Text('物种简介', style: Theme.of(context).textTheme.titleLarge),
                  ],
                ),
                const SizedBox(height: 14),
                Text(
                  record.speciesIntro,
                  style: Theme.of(context).textTheme.bodyLarge,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

Widget _buildImage(String imageB64) {
  final bytes = _tryDecodeImage(imageB64);
  if (bytes == null) {
    return const Center(
      child: Icon(Icons.image_outlined, color: Colors.white, size: 64),
    );
  }

  return Image.memory(
    bytes,
    fit: BoxFit.cover,
    width: double.infinity,
    height: double.infinity,
    errorBuilder: (context, error, stackTrace) {
      return const Center(
        child: Icon(Icons.broken_image_outlined, color: Colors.white, size: 64),
      );
    },
  );
}

Uint8List? _tryDecodeImage(String imageB64) {
  final normalized = imageB64.trim();
  if (normalized.isEmpty) {
    return null;
  }

  try {
    return base64Decode(normalized);
  } on FormatException {
    return null;
  }
}

class _DetailRow extends StatelessWidget {
  const _DetailRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(20),
        ),
        child: Row(
          children: [
            Text(
              label,
              style: Theme.of(
                context,
              ).textTheme.bodyMedium?.copyWith(color: Colors.black54),
            ),
            const Spacer(),
            Text(value, style: Theme.of(context).textTheme.titleMedium),
          ],
        ),
      ),
    );
  }
}
