"""
Agent Core 端到端测试：推理请求链路。

验证 orchestrator 的 classify → plan → execute → synthesize 四步流水线
能否以真实 DeepSeek API + 本地推理引擎完整跑通。

用法：
    cd bms_copilot
    python tests/test_inference_flow.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

# ------------------------------------------------------------------
# 确保 src 包可导入
# ------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

# ------------------------------------------------------------------
# API Key: 从 schemas.py 示例中提取（用户指示直接使用该条 key）
# 在加载配置前注入环境变量，config_loader 会通过 AgentConfig.normalized()
# 读取 DEEPSEEK_API_KEY
# ------------------------------------------------------------------
os.environ["DEEPSEEK_API_KEY"] = "sk-ef96483db18e4cad96e7579d849d023c"

from src.iface.agent.tools import ITool, IToolRegistry
from src.iface.agent.runtime import AgentRuntimeContext
from src.models.agent.schemas import (
    AgentRequest,
    AgentResponse,
    ImageRef,
    RequestContext,
    RequestMeta,
    RunStatus,
    ToolStatus,
)
from src.models.sys.config_loader import load_project_config_from_toml
from src.agent_core.provider.deepseek import DeepSeekChatProvider
from src.agent_core.orchestrator.agent import AgentOrchestrator
from src.agent_core.orchestrator.router import PromptIntentClassifier
from src.agent_core.orchestrator.planner import PromptToolPlanner
from src.agent_core.orchestrator.synthesizer import PromptResponseSynthesizer
from src.agent_core.tools.inference import ImageInferenceTool


# ==================================================================
# 简单的 ToolRegistry 实现
# ==================================================================

class DictToolRegistry(IToolRegistry):
    """基于内存 dict 的工具注册表。"""

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
# 简单的时间线记录器（替代 audit sink）
# ==================================================================

class Timeline:
    """轻量流水线步骤记录器，替代 audit sink 的功能。"""

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
# 主流程
# ==================================================================

async def main() -> None:
    print("=" * 60)
    print("  Agent Core 端到端测试：推理请求")
    print("=" * 60)

    t = Timeline()

    # ---- 1. 加载配置 ----
    t.step("加载配置")
    settings_path = _PROJECT_ROOT / "settings.toml"
    config = load_project_config_from_toml(str(settings_path))

    agent_cfg = config.agent
    if agent_cfg is None:
        print("[错误] settings.toml 中缺少 [agent] 配置")
        return

    print(f"        provider = {agent_cfg.provider}")
    print(f"        model    = {agent_cfg.model}")
    key_tail = agent_cfg.api_key[-4:] if agent_cfg.api_key else "(空)"
    print(f"        api_key  = ...{key_tail}")

    # ---- 2. 创建 DeepSeek Provider ----
    t.step("创建 Provider")
    chat_provider = DeepSeekChatProvider(config=agent_cfg)

    # ---- 3. 创建并注册工具 ----
    t.step("初始化推理工具")
    inference_tool = ImageInferenceTool(
        config=config,
        base_dir=_PROJECT_ROOT,
        enable_species_resolver=False,
    )

    registry = DictToolRegistry()
    registry.register(inference_tool)
    print(f"        已注册: {inference_tool.name}")

    # ---- 4. 创建 Orchestrator（注入相同的 model 名）----
    t.step("装配 Orchestrator")
    orchestrator = AgentOrchestrator(
        tool_registry=registry,
        classifier=PromptIntentClassifier(
            provider=chat_provider, model=agent_cfg.model
        ),
        planner=PromptToolPlanner(
            provider=chat_provider, model=agent_cfg.model
        ),
        synthesizer=PromptResponseSynthesizer(
            provider=chat_provider, model=agent_cfg.model
        ),
    )

    # ---- 5. 读取测试图片 ----
    image_path = _PROJECT_ROOT / "tests" / "014-309468415-558447005.jpg"
    if not image_path.exists():
        print(f"\n[错误] 测试图片不存在: {image_path}")
        return

    image_bytes = image_path.read_bytes()
    t.step("读取测试图片", file=image_path.name, size=f"{len(image_bytes)} bytes")

    # ---- 6. 构造请求 ----
    request = AgentRequest(
        request_id=str(uuid4()),
        session_id=str(uuid4()),
        user_id="test-user",
        text="帮我识别这张图片中的鸟类",
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
    t.step("构造请求", text=request.text, images=len(request.images))

    # ---- 7. 执行编排流水线 ----
    print()
    print("  ── 开始执行编排流水线 ──")
    print()

    try:
        response: AgentResponse = await orchestrator.run(request)
    except Exception as exc:
        print(f"\n  [异常] 编排执行失败: {exc}")
        import traceback

        traceback.print_exc()
        return

    # ---- 8. 输出结果 ----
    print()
    print("  ── 执行完成 ──")
    print()

    t.step(
        "最终结果",
        status=response.status.value,
        intent=response.debug.intent,
        tools=", ".join(response.debug.tools),
        provider=response.debug.provider or "(无)",
    )

    print()
    print(f"  status       = {response.status}")
    print(f"  intent       = {response.debug.intent}")
    print(f"  tools        = {response.debug.tools}")
    print(f"  provider     = {response.debug.provider}")
    print(f"  model        = {response.debug.model}")

    if response.answer.text:
        print(f"\n  answer.text:")
        for line in response.answer.text.strip().split("\n"):
            print(f"    {line}")

    if response.answer.structured:
        import json

        print(f"\n  answer.structured:")
        print(f"    {json.dumps(response.answer.structured, ensure_ascii=False, indent=4)}")

    if response.citations:
        print(f"\n  citations ({len(response.citations)}):")
        for c in response.citations:
            print(f"    - [{c.source_id}] {c.title}")

    print()
    t.print_summary()
    print()
    print("=" * 60)
    print("  测试完成")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
