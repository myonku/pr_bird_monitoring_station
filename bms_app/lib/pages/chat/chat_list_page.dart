import 'package:flutter/material.dart';

import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';
import 'package:bms_app/pages/chat/chat_detail_page.dart';

/// 聊天第一层：会话列表 + 底部输入框（新建会话）。
class ChatListPage extends StatefulWidget {
  const ChatListPage({super.key, required this.monitoringController});

  final MonitoringController monitoringController;

  @override
  State<ChatListPage> createState() => _ChatListPageState();
}

class _ChatListPageState extends State<ChatListPage> {
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  bool _isLoading = false;
  String? _errorMessage;
  List<ChatSessionSummaryResponse> _sessions = const [];

  @override
  void initState() {
    super.initState();
    _loadSessions();
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadSessions() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final userId = _resolveUserId();
      final response = await widget.monitoringController.chatSessionList(
        ChatSessionListRequest(userId: userId, limit: 50),
      );
      if (!mounted) return;
      setState(() {
        _sessions = response.sessions;
        _isLoading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isLoading = false;
        _errorMessage = e.toString();
      });
    }
  }

  Future<void> _onSend(String text) async {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return;

    final userId = _resolveUserId();

    // 1. 创建新会话
    ChatSessionCreateResponse created;
    try {
      created = await widget.monitoringController.chatSessionCreate(
        ChatSessionCreateRequest(userId: userId, title: trimmed),
      );
    } catch (e) {
      if (!mounted) return;
      _showSnackBar('创建会话失败: $e');
      return;
    }

    // 2. 发送第一条消息
    ChatSendResponse sent;
    try {
      sent = await widget.monitoringController.chatSend(
        ChatSendRequest(
          sessionId: created.sessionId,
          userId: userId,
          text: trimmed,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      _showSnackBar('发送失败: $e');
      return;
    }

    _inputController.clear();

    // 3. 进入聊天详情页
    if (!mounted) return;
    await Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => ChatDetailPage(
          monitoringController: widget.monitoringController,
          sessionId: created.sessionId,
          initialMessages: [
            ChatMessageItemResponse(
              turnIndex: 0,
              requestId: sent.requestId,
              role: 'user',
              text: trimmed,
              createdAtMs: DateTime.now().millisecondsSinceEpoch,
            ),
            if (sent.text.isNotEmpty)
              ChatMessageItemResponse(
                turnIndex: 0,
                requestId: sent.requestId,
                role: 'assistant',
                text: sent.text,
                intentType: sent.intentType,
                toolNames: sent.toolNames,
                createdAtMs: DateTime.now().millisecondsSinceEpoch,
              ),
          ],
        ),
      ),
    );

    // 返回后刷新列表
    if (!mounted) return;
    _loadSessions();
  }

  void _openSession(ChatSessionSummaryResponse session) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => ChatDetailPage(
          monitoringController: widget.monitoringController,
          sessionId: session.sessionId,
          initialMessages: null,
        ),
      ),
    ).then((_) {
      if (!mounted) return;
      _loadSessions();
    });
  }

  String _resolveUserId() {
    final identifier = widget.monitoringController.loginIdentifier;
    return (identifier ?? '').trim().isEmpty
        ? 'default_user'
        : identifier!.trim();
  }

  void _showSnackBar(String message) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message)),
    );
  }

  String _formatTime(int ms) {
    final dt =
        DateTime.fromMillisecondsSinceEpoch(ms).toLocal();
    final now = DateTime.now();
    final diff = now.difference(dt);

    if (diff.inMinutes < 1) return '刚刚';
    if (diff.inHours < 1) return '${diff.inMinutes}分钟前';
    if (diff.inDays < 1) return '${diff.inHours}小时前';
    if (diff.inDays < 7) return '${diff.inDays}天前';
    return '${dt.month}/${dt.day}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Column(
      children: [
        // ── 会话列表 ──
        Expanded(
          child: _buildSessionList(theme),
        ),

        // ── 底部输入框 ──
        _buildInputBar(theme),
      ],
    );
  }

  Widget _buildSessionList(ThemeData theme) {
    if (_isLoading && _sessions.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_errorMessage != null && _sessions.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.cloud_off, size: 48, color: theme.colorScheme.error),
              const SizedBox(height: 12),
              Text('加载失败', style: theme.textTheme.titleMedium),
              const SizedBox(height: 6),
              Text(
                _errorMessage!,
                textAlign: TextAlign.center,
                style: theme.textTheme.bodySmall?.copyWith(color: Colors.black54),
              ),
              const SizedBox(height: 16),
              FilledButton.tonalIcon(
                onPressed: _loadSessions,
                icon: const Icon(Icons.refresh),
                label: const Text('重试'),
              ),
            ],
          ),
        ),
      );
    }

    if (_sessions.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.chat_bubble_outline,
                  size: 48, color: theme.colorScheme.primary.withValues(alpha: 0.4)),
              const SizedBox(height: 12),
              Text('暂无会话', style: theme.textTheme.titleMedium),
              const SizedBox(height: 6),
              Text(
                '在下方输入文字开始新的对话',
                style: theme.textTheme.bodySmall?.copyWith(color: Colors.black54),
              ),
            ],
          ),
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _loadSessions,
      child: ListView.separated(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        itemCount: _sessions.length,
        separatorBuilder: (_, _) => const Divider(height: 1, indent: 16, endIndent: 16),
        itemBuilder: (context, index) {
          final session = _sessions[index];
          return _SessionTile(
            session: session,
            timeLabel: _formatTime(session.updatedAtMs),
            onTap: () => _openSession(session),
          );
        },
      ),
    );
  }

  Widget _buildInputBar(ThemeData theme) {
    return Container(
      padding: EdgeInsets.only(
        left: 16,
        right: 8,
        top: 8,
        bottom: MediaQuery.of(context).padding.bottom + 8,
      ),
      decoration: BoxDecoration(
        color: Colors.white,
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.06),
            blurRadius: 8,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _inputController,
              textInputAction: TextInputAction.send,
              decoration: InputDecoration(
                hintText: '输入消息开始新会话...',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(24),
                  borderSide: BorderSide.none,
                ),
                filled: true,
                fillColor: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
                isDense: true,
              ),
              onSubmitted: _onSend,
            ),
          ),
          const SizedBox(width: 6),
          IconButton.filled(
            onPressed: () => _onSend(_inputController.text),
            icon: const Icon(Icons.send, size: 20),
            style: IconButton.styleFrom(
              backgroundColor: theme.colorScheme.primary,
              foregroundColor: theme.colorScheme.onPrimary,
            ),
          ),
        ],
      ),
    );
  }
}

/// 单个会话条目组件。
class _SessionTile extends StatelessWidget {
  const _SessionTile({
    required this.session,
    required this.timeLabel,
    required this.onTap,
  });

  final ChatSessionSummaryResponse session;
  final String timeLabel;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final title = session.title.trim().isNotEmpty
        ? session.title.trim()
        : (session.lastText.trim().isNotEmpty
            ? session.lastText.trim()
            : '新会话');

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 4),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Container(
              width: 42,
              height: 42,
              decoration: BoxDecoration(
                color: theme.colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Icon(
                Icons.smart_toy_outlined,
                color: theme.colorScheme.onPrimaryContainer,
                size: 22,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const SizedBox(height: 3),
                  if (session.lastText.trim().isNotEmpty)
                    Text(
                      session.lastText,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: Colors.black54,
                      ),
                    ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            Text(
              timeLabel,
              style: theme.textTheme.bodySmall?.copyWith(
                color: Colors.black45,
                fontSize: 11,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
