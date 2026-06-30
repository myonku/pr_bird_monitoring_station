
# Agent 功能模块设计说明（简要版）

版本：0.1.0
状态：Draft
目标：作为 AI 助手功能模块实现准绳（仅覆盖 Agent Core，不覆盖完整服务框架）

---

## 1. 设计目标与范围

### 1.1 目标

在现有鸟类监测系统中新增一个 **Agent 功能模块**，用于提供统一的智能交互能力，包括：

- 自然语言搜索与查询
- 统计问答
- 图片识别请求编排（上传图片后调用后端推理能力）
- 物种知识补充（RAG）
- 结果整合与可解释输出

该模块定位为“**LLM + Tool Orchestration + RAG**”的应用核心，而非自治型复杂多智能体系统。

### 1.2 范围（In Scope）

- 意图识别与参数抽取
- 工具调用编排与执行
- 知识检索增强（RAG）
- 统一响应生成
- 会话内上下文管理（短期）
- 多模型提供商抽象（OAI / Anthropic / DeepSeek 等）

### 1.3 非范围（Out of Scope）

- 完整服务模块通信框架（网关、鉴权链路、流量站等）
- 具体基础设施部署编排
- 复杂长期记忆系统（跨月级用户画像）
- 多智能体协同框架（第一阶段不引入）

---

## 2. 模块定位与核心原则

### 2.1 模块定位

Agent Core 是独立的业务能力核心，负责：

1. 解析用户请求
2. 规划执行步骤
3. 调用业务工具能力
4. 汇总结果并输出统一响应

### 2.2 核心原则

1. **工具优先**：真实数据获取与执行由工具层完成，LLM 不直接替代工具计算。
2. **结构优先**：模块内各层均以结构化对象传递，避免自由文本耦合。
3. **显式编排**：流程可追踪、可回放、可调试，不做黑盒自治。
4. **可替换模型源**：模型调用通过 Provider 抽象，支持快速切换。
5. **渐进增强**：先单 Agent + 少量工具，后续再扩展工作流复杂度。

---

## 3. 基础功能定义

### 3.1 查询类（Search）

- 输入自然语言查询（可含时间、地点、鸟种等条件）
- 抽取过滤参数并调用检索工具
- 返回结构化记录摘要与自然语言解释

### 3.2 统计类（Statistics）

- 输入统计问题（计数、趋势、Top-K、分组）
- 生成统计查询参数并调用统计工具
- 返回统计结果（结构化）+ 说明文本

### 3.3 识别类（Inference）

- 输入文本 + 图片（可选）
- 调用推理工具（检测/分类）
- 输出识别结果、置信度、简要解释

### 3.4 知识问答类（RAG）

- 针对物种资料、识别说明等问题进行向量检索
- 基于检索证据生成回答
- 返回答案及引用片段（可选）

### 3.5 混合类（Composite）

- 同一请求涉及多个能力（如“识别+统计+说明”）
- 编排层按依赖顺序调多个工具
- 聚合输出单一响应

---

## 4. 模块内输入输出契约（通信层对接重点）

> 说明：此处为 Agent Core 内部/边界契约，不限定传输协议。可映射到 gRPC message / internal DTO。

## 4.1 输入对象：AgentRequest

```json
{
  "request_id": "uuid",
  "session_id": "uuid",
  "user_id": "string",
  "text": "string",
  "images": [
    {
      "image_id": "string",
      "uri": "string",
      "mime_type": "image/jpeg"
    }
  ],
  "context": {
    "locale": "zh-CN",
    "timezone": "Asia/Shanghai",
    "client_type": "app"
  },
  "metadata": {
    "trace_id": "string",
    "timestamp_ms": 0
  }
}
```

## 4.2 中间对象：IntentResult

```json
{
  "intent_type": "search|statistics|inference|knowledge|composite",
  "confidence": 0.0,
  "slots": {
    "species": "string",
    "time_range": "string",
    "location": "string",
    "metrics": ["count"]
  },
  "need_rag": false,
  "tool_plan_hint": ["search_tool"]
}
```

## 4.3 中间对象：ToolCall / ToolResult

```json
{
  "tool_name": "search_tool",
  "arguments": {},
  "timeout_ms": 3000
}
```

```json
{
  "tool_name": "search_tool",
  "status": "ok|error",
  "payload": {},
  "error": {
    "code": "string",
    "message": "string"
  },
  "latency_ms": 120
}
```

## 4.4 输出对象：AgentResponse

```json
{
  "request_id": "uuid",
  "session_id": "uuid",
  "status": "ok|partial|error",
  "answer": {
    "text": "string",
    "structured": {},
    "cards": []
  },
  "citations": [
    {
      "source_id": "string",
      "title": "string",
      "snippet": "string"
    }
  ],
  "debug": {
    "intent": "search",
    "tools": ["search_tool"],
    "provider": "openai",
    "model": "gpt-4o-mini"
  }
}
```

---

## 5. 分层设计

建议分 6 层：

1. **Interface Schema 层**

   - 定义请求/响应与中间对象（DTO/Schema）
2. **Intent & Planning 层**

   - 意图识别、参数抽取、执行计划生成
3. **Orchestration 层（核心）**

   - 调度流程、依赖顺序、失败回退、结果聚合
4. **Tool Adapter 层**

   - 对接检索、统计、推理、历史查询等能力
5. **Knowledge/RAG 层**

   - 文档切分、Embedding、向量检索、引用组装
6. **Model Provider 层**

   - 封装 OAI / Anthropic / DeepSeek 等模型调用差异

---

## 6. 模型提供商抽象设计（多 Provider 快速切换）

### 6.1 目标

支持多个外部模型提供商并实现低成本切换，避免业务逻辑绑定单一 API。

### 6.2 抽象接口（建议）

- `ChatProvider.generate(messages, options) -> ChatResult`
- `EmbeddingProvider.embed(texts, options) -> EmbeddingResult`
- `VisionProvider.describe(image, prompt, options) -> VisionResult`（可选）

### 6.3 Provider Registry

- 通过配置中心/环境变量选择默认 provider 与 model
- 支持请求级覆盖（灰度/AB）
- 支持 fallback 策略（主 provider 失败时切换备 provider）

### 6.4 统一错误语义

对外统一错误码，内部映射 provider 特有错误：

- RATE_LIMIT
- TIMEOUT
- AUTH_FAILED
- INVALID_REQUEST
- PROVIDER_UNAVAILABLE

---

## 7. 设计方向（第一阶段）

### 7.1 架构风格

- 单 Agent（非多代理）
- 显式状态编排（可选有限状态机）
- 工具调用数量可控（先 3~5 个）

### 7.2 重点能力

- 高质量意图路由
- 稳定工具调用
- RAG 证据回答
- 结构化输出

### 7.3 暂不引入

- 长链自治规划
- 自动执行高风险动作
- 复杂角色协作 Agent

---

## 8. 推荐工具集（初始）

1. `search_records_tool`：监测记录检索
2. `stats_query_tool`：统计查询
3. `image_inference_tool`：识别请求编排
4. `species_kb_tool`：物种知识检索（RAG）
5. `session_context_tool`（可选）：会话上下文补充

---

## 9. 运行流程（简化）

1. 接收 `AgentRequest`
2. 意图识别 + 参数抽取（IntentResult）
3. 生成 Tool Plan
4. 顺序/并行执行工具（按依赖）
5. 若需 RAG，则补检索证据
6. 汇总结果并生成 `AgentResponse`
7. 写入运行日志（请求、工具、模型、耗时）

---

## 10. 可观测性与评估（最小集）

### 10.1 最小日志字段

- request_id / session_id / trace_id
- intent_type
- tool_calls（名称、参数摘要、耗时、状态）
- provider / model
- token 用量（如可得）
- end_to_end latency
- error_code / error_stage

### 10.2 最小评估指标

- 意图识别准确率
- 工具调用成功率
- 回答可用率（人工抽样）
- 平均延迟
- 单请求成本

---

## 11. 演进路线

### Phase 1：最小可用（MVP）

- 单轮请求
- 查询/统计/识别三类能力
- 基础 RAG（物种资料）
- 单 provider + 备用 provider

### Phase 2：稳定化

- 多 provider 路由 + fallback
- 会话连续追问
- 结构化卡片输出标准化
- 引入基础评估集与回归测试

### Phase 3：增强编排

- 多步复合任务（composite）
- 条件分支与重试策略增强
- 更细粒度安全策略与确认机制
- 更强的检索重排（rerank）

### Phase 4：产品化能力

- 多租户/多环境配置
- Prompt/策略版本化
- 在线质量监控与告警
- 灰度发布与 A/B 策略

---

## 12. 实施约束（建议）

1. Agent Core 仅依赖抽象工具接口，不直接耦合具体存储实现。
2. 工具返回必须结构化，禁止“仅文本返回”进入编排层。
3. Provider 变更不得影响上层 Orchestrator 逻辑。
4. 每次新增能力先补契约，再补实现，再补评估样例。
5. 任何回答型输出都应可追溯到工具结果或检索证据。

---

## 13. 一句话准绳

> Agent Core 的职责是“理解 + 编排 + 汇总”，而不是替代业务工具本身。
> 先保证可控、可测、可替换，再逐步增强智能性。

