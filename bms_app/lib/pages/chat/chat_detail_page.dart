import 'package:flutter/material.dart';

import 'package:bms_app/controller/controller.dart';
import 'package:bms_app/models/transport/client_req_dto.dart';
import 'package:bms_app/models/transport/client_resp_dto.dart';

/// 聊天第二层：单个会话的消息详情页。
class ChatDetailPage extends StatefulWidget {
  const ChatDetailPage({
    super.key,
    required this.monitoringController,
    required this.sessionId,
    this.initialMessages,
  });

  final MonitoringController monitoringController;
  final String sessionId;
  final List<ChatMessageItemResponse>? initialMessages;

  @override
  State<ChatDetailPage> createState() => _ChatDetailPageState();
}

class _ChatDetailPageState extends State<ChatDetailPage> {
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();

  bool _isLoading = false;
  String? _errorMessage;
  List<ChatMessageItemResponse> _messages = [];
  String _sessionTitle = '智能助手';
  bool _isSending = false;

  @override
  void initState() {
    super.initState();
    if (widget.initialMessages != null) {
      _messages = widget.initialMessages!;
    } else {
      _loadMessages();
    }
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadMessages() async {
    setState(() {
      _isLoading = true;
      _errorMessage = null;
    });

    try {
      final userId = _resolveUserId();
      final detail = await widget.monitoringController.chatSessionDetail(
        ChatSessionGetRequest(
          sessionId: widget.sessionId,
          userId: userId,
          messageLimit: 100,
        ),
      );
      if (!mounted) return;
      setState(() {
        _messages = detail.messages;
        _sessionTitle = detail.model.trim().isNotEmpty
            ? '智能助手'
            : '智能助手';
        _isLoading = false;
      });
      _scrollToBottom();
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
    if (trimmed.isEmpty || _isSending) return;

    final userId = _resolveUserId();
    _inputController.clear();

    // 立即添加用户消息
    final userMsg = ChatMessageItemResponse(
      turnIndex: _messages.length,
      requestId: '',
      role: 'user',
      text: trimmed,
      createdAtMs: DateTime.now().millisecondsSinceEpoch,
    );

    setState(() {
      _messages = [..._messages, userMsg];
      _isSending = true;
    });
    _scrollToBottom();

    try {
      final response = await widget.monitoringController.chatSend(
        ChatSendRequest(
          sessionId: widget.sessionId,
          userId: userId,
          text: trimmed,
        ),
      );

      if (!mounted) return;

      // 更新用户消息的 requestId
      final updatedMessages = List<ChatMessageItemResponse>.of(_messages);
      if (updatedMessages.isNotEmpty && response.requestId.isNotEmpty) {
        final last = updatedMessages.removeLast();
        updatedMessages.add(ChatMessageItemResponse(
          turnIndex: last.turnIndex,
          requestId: response.requestId,
          role: last.role,
          text: last.text,
          createdAtMs: last.createdAtMs,
        ));
      }

      // 添加助手回复
      if (response.text.isNotEmpty) {
        updatedMessages.add(ChatMessageItemResponse(
          turnIndex: updatedMessages.length,
          requestId: response.requestId,
          role: 'assistant',
          text: response.text,
          intentType: response.intentType,
          toolNames: response.toolNames,
          createdAtMs: DateTime.now().millisecondsSinceEpoch,
        ));
      }

      setState(() {
        _messages = updatedMessages;
        _isSending = false;
      });
      _scrollToBottom();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _isSending = false;
      });
      _showSnackBar('发送失败: $e');
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_sessionTitle),
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: Column(
        children: [
          // ── 消息列表 ──
          Expanded(child: _buildMessageList()),

          // ── 底部输入框 ──
          _buildInputBar(),
        ],
      ),
    );
  }

  Widget _buildMessageList() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_errorMessage != null && _messages.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.cloud_off,
                  size: 48,
                  color: Theme.of(context).colorScheme.error),
              const SizedBox(height: 12),
              Text('加载失败', style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 6),
              Text(
                _errorMessage!,
                textAlign: TextAlign.center,
                style: Theme.of(context)
                    .textTheme
                    .bodySmall
                    ?.copyWith(color: Colors.black54),
              ),
              const SizedBox(height: 16),
              FilledButton.tonalIcon(
                onPressed: _loadMessages,
                icon: const Icon(Icons.refresh),
                label: const Text('重试'),
              ),
            ],
          ),
        ),
      );
    }

    if (_messages.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.chat_bubble_outline,
                size: 48,
                color: Theme.of(context)
                    .colorScheme
                    .primary
                    .withValues(alpha: 0.4)),
            const SizedBox(height: 12),
            Text('开始对话', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(
              '在下方输入您的问题',
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: Colors.black54),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      controller: _scrollController,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      itemCount: _messages.length,
      itemBuilder: (context, index) {
        final msg = _messages[index];
        final isUser = msg.role == 'user';
        return _MessageBubble(
          message: msg,
          isUser: isUser,
          showTools: msg.toolNames.isNotEmpty && !isUser,
        );
      },
    );
  }

  Widget _buildInputBar() {
    final theme = Theme.of(context);

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
              enabled: !_isSending,
              decoration: InputDecoration(
                hintText: '输入消息...',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(24),
                  borderSide: BorderSide.none,
                ),
                filled: true,
                fillColor: theme.colorScheme.surfaceContainerHighest
                    .withValues(alpha: 0.5),
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
                isDense: true,
              ),
              onSubmitted: _onSend,
            ),
          ),
          const SizedBox(width: 6),
          IconButton.filled(
            onPressed:
                _isSending ? null : () => _onSend(_inputController.text),
            icon: _isSending
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: Colors.white,
                    ),
                  )
                : const Icon(Icons.send, size: 20),
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

/// 单条消息气泡组件。
class _MessageBubble extends StatelessWidget {
  const _MessageBubble({
    required this.message,
    required this.isUser,
    this.showTools = false,
  });

  final ChatMessageItemResponse message;
  final bool isUser;
  final bool showTools;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Column(
        crossAxisAlignment:
            isUser ? CrossAxisAlignment.end : CrossAxisAlignment.start,
        children: [
          // 工具标签
          if (showTools) ...[
            Padding(
              padding: const EdgeInsets.only(left: 4, bottom: 4),
              child: Wrap(
                spacing: 4,
                children: message.toolNames
                    .map(
                      (name) => Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: theme.colorScheme.tertiaryContainer,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Text(
                          name,
                          style: TextStyle(
                            fontSize: 11,
                            color: theme.colorScheme.onTertiaryContainer,
                          ),
                        ),
                      ),
                    )
                    .toList(growable: false),
              ),
            ),
          ],

          // 气泡
          Container(
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.75,
            ),
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            decoration: BoxDecoration(
              color: isUser
                  ? theme.colorScheme.primary
                  : theme.colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(20),
                topRight: const Radius.circular(20),
                bottomLeft: Radius.circular(isUser ? 20 : 4),
                bottomRight: Radius.circular(isUser ? 4 : 20),
              ),
            ),
            child: Text(
              message.text,
              style: TextStyle(
                fontSize: 15,
                height: 1.45,
                color: isUser
                    ? theme.colorScheme.onPrimary
                    : theme.colorScheme.onSurface,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
