"""
Agent Core 多轮会话端到端测试。

场景：
  第 1 轮：用户上传图片 + 询问鸟种信息
           → COMPOSITE 意图 → image_inference_tool + query_records_tool

  第 2 轮：询问该种别上一次被识别到的时间
           → SEARCH 意图 → query_records_tool

用法：
    cd bms_copilot
    $env:DEEPSEEK_API_KEY = ""
    python tests/test_multi_turn_conversation.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# API Key — 从 api_key.key 读取
os.environ["DEEPSEEK_API_KEY"] = ""

from src.iface.agent.tools import ITool, IToolRegistry
from src.iface.agent.runtime import AgentRuntimeContext
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    ImageRef,
    RequestContext,
    RequestMeta,
)
from src.models.sys.config_loader import load_project_config_from_toml
from src.agent_core.provider.chat_provider.deepseek import DeepSeekChatProvider
from src.agent_core.orchestrator.agent import AgentOrchestrator
from src.agent_core.orchestrator.router import PromptIntentClassifier
from src.agent_core.orchestrator.planner import PromptToolPlanner
from src.agent_core.orchestrator.synthesizer import PromptResponseSynthesizer
from src.agent_core.tools.inference import ImageInferenceTool
from src.agent_core.tools.query import QueryRecordsTool
from src.modules.query.engine import QueryEngine
from src.repo.mysql_client import MySQLClient
from src.repo.mongo_client import MongoDBClient
from src.models.business.event import MonitoringRecord, EdgeEventEnvelope


# ==================================================================
# ToolRegistry
# ==================================================================

class DictToolRegistry(IToolRegistry):
    def __init__(self) -> None:
        self._tools: dict[str, ITool] = {}

    def register(self, tool: ITool) -> None:
        self._tools[tool.name] = tool

    def get(self, tool_name: str) -> ITool:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise KeyError(f"tool not found: {tool_name}")
        return tool

    def has(self, tool_name: str) -> bool:
        return tool_name in self._tools

    def list_tools(self) -> dict[str, ITool]:
        return dict(self._tools)


# ==================================================================
# Timeline
# ==================================================================

class Timeline:
    def __init__(self) -> None:
        self._steps: list[dict[str, Any]] = []
        self._start = time.time()

    def step(self, name: str, **fields: Any) -> None:
        elapsed = time.time() - self._start
        self._steps.append({"elapsed_ms": int(elapsed * 1000), "step": name, **fields})
        print(f"  [{elapsed:6.1f}s] {name}", end="")
        if fields:
            summary = ", ".join(f"{k}={v}" for k, v in fields.items())
            print(f"  │ {summary}")
        else:
            print()

    def print_summary(self) -> None:
        total = time.time() - self._start
        print(f"\n  —— 总耗时 {total:.1f}s, {len(self._steps)} 步 ——")


# ==================================================================
# 打印响应详情
# ==================================================================

def print_response(turn: int, tag: str, resp: AgentResponse) -> None:
    print(f"\n  ── 第 {turn} 轮结果 [{tag}] ──")
    print(f"  status   = {resp.status}")
    print(f"  intent   = {resp.debug.intent}")
    print(f"  tools    = {resp.debug.tools}")

    if resp.answer.structured:
        import json
        print(f"  structured = {json.dumps(resp.answer.structured, ensure_ascii=False, indent=2)[:1200]}")

    text = (resp.answer.text or "").strip()
    if text:
        preview = text[:600]
        print(f"  answer.text = {preview}")


# ==================================================================
# 主流程
# ==================================================================

async def main() -> None:
    print("=" * 60)
    print("  Agent Core 多轮会话端到端测试")
    print("=" * 60)

    t = Timeline()
    session_id = str(uuid4())

    # ---- 1. 加载配置 ----
    t.step("加载配置")
    config = load_project_config_from_toml(str(_PROJECT_ROOT / "settings.toml"))
    assert config.agent is not None
    print(f"        provider = {config.agent.provider}, model = {config.agent.model}")
    print(f"        api_key  = ...{config.agent.api_key[-4:]}")

    # ---- 2. Provider ----
    t.step("创建 Provider")
    chat_provider = DeepSeekChatProvider(config=config.agent)

    # ---- 3. 初始化数据库连接 ----
    t.step("初始化数据库连接")

    mysql_client: MySQLClient | None = None
    mongo_client: MongoDBClient | None = None

    if config.mysql is not None:
        mysql_client = MySQLClient(config)
        try:
            await mysql_client.connect()
            print("        MySQL 已连接")
        except Exception as exc:
            print(f"        MySQL 连接失败 (非致命): {exc}")
            mysql_client = None

    if config.mongo is not None:
        mongo_client = MongoDBClient(config)
        try:
            await mongo_client.connect(
                document_models=[MonitoringRecord, EdgeEventEnvelope]
            )
            print("        MongoDB 已连接")
        except Exception as exc:
            print(f"        MongoDB 连接失败 (非致命): {exc}")
            mongo_client = None

    # ---- 4. 创建工具 ----
    t.step("初始化工具")

    inference_tool = ImageInferenceTool(
        config=config,
        base_dir=_PROJECT_ROOT,
        enable_species_resolver=False,
    )
    print(f"        推理工具: {inference_tool.name}")

    query_engine = QueryEngine(
        mongo_client=mongo_client,
        mysql_client=mysql_client,
    )
    query_tool = QueryRecordsTool(engine=query_engine)
    print(f"        查询工具: {query_tool.name}")

    registry = DictToolRegistry()
    registry.register(inference_tool)
    registry.register(query_tool)

    # ---- 5. Orchestrator ----
    t.step("装配 Orchestrator")
    orchestrator = AgentOrchestrator(
        tool_registry=registry,
        classifier=PromptIntentClassifier(
            provider=chat_provider, model=config.agent.model
        ),
        planner=PromptToolPlanner(
            provider=chat_provider, model=config.agent.model
        ),
        synthesizer=PromptResponseSynthesizer(
            provider=chat_provider, model=config.agent.model
        ),
    )

    # ---- 6. 读取测试图片 ----
    image_path = _PROJECT_ROOT / "tests" / "014-309468415-558447005.jpg"
    assert image_path.exists(), f"图片不存在: {image_path}"
    image_bytes = image_path.read_bytes()
    t.step("读取图片", file=image_path.name, size=f"{len(image_bytes)} bytes")

    # ================================================================
    # 第 1 轮：识别 + 鸟种简介
    # ================================================================
    print()
    print("  ════════════════════════════════════════════════════════")
    print("  第 1 轮：上传图片 + 询问鸟种信息")
    print("  ════════════════════════════════════════════════════════")
    print()

    req1 = AgentRequest(
        request_id=str(uuid4()),
        session_id=session_id,
        user_id="test-user",
        text="帮我识别这张图片中的鸟类，并告诉我它的简介",
        images=[
            ImageRef(
                image_id="test-img-1",
                data=image_bytes,
                mime_type="image/jpeg",
                filename=image_path.name,
                size_bytes=len(image_bytes),
            )
        ],
        context=RequestContext(locale="zh-CN", timezone="Asia/Shanghai"),
        metadata=RequestMeta(trace_id=str(uuid4())),
    )
    t.step("第1轮 请求", text=req1.text[:50], images=len(req1.images))

    try:
        resp1 = await orchestrator.run(req1)
        print_response(1, "完成", resp1)
    except Exception as exc:
        print(f"\n  [异常] 第1轮失败: {exc}")
        import traceback
        traceback.print_exc()
        return

    # ================================================================
    # 第 2 轮：查询该种别上次被识别的时间
    # ================================================================
    print()
    print("  ════════════════════════════════════════════════════════")
    print("  第 2 轮：询问该种别上一次被识别到的时间")
    print("  ════════════════════════════════════════════════════════")
    print()

    # 从第 1 轮的推理结果中提取物种名
    species_name = "unknown"
    try:
        tr = resp1.answer.structured.get("tool_results", [])
        for r in tr:
            payload = r.get("payload", {})
            results = payload.get("results", [])
            for item in results:
                label = item.get("label") or item.get("species", {}).get("display_name", "")
                if label:
                    species_name = label
                    break
    except Exception:
        pass
    print(f"  推断的物种名: {species_name}")

    req2 = AgentRequest(
        request_id=str(uuid4()),
        session_id=session_id,
        user_id="test-user",
        text=f"{species_name}上次被识别到是什么时候",
        images=[],
        context=RequestContext(locale="zh-CN", timezone="Asia/Shanghai"),
        metadata=RequestMeta(trace_id=str(uuid4())),
    )
    t.step("第2轮 请求", text=req2.text)

    try:
        resp2 = await orchestrator.run(req2)
        print_response(2, "完成", resp2)
    except Exception as exc:
        print(f"\n  [异常] 第2轮失败: {exc}")
        import traceback
        traceback.print_exc()
        return

    # ================================================================
    # 汇总
    # ================================================================
    print()
    print("  ════════════════════════════════════════════════════════")
    print("  测试汇总")
    print("  ════════════════════════════════════════════════════════")
    t.print_summary()
    status1 = resp1.status.value if hasattr(resp1.status, "value") else resp1.status
    status2 = resp2.status.value if hasattr(resp2.status, "value") else resp2.status
    print(f"  第1轮: intent={resp1.debug.intent}, tools={resp1.debug.tools}, status={status1}")
    print(f"  第2轮: intent={resp2.debug.intent}, tools={resp2.debug.tools}, status={status2}")
    print(f"  session_id = {session_id}")
    print()
    print("=" * 60)
    print("  测试完成")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
