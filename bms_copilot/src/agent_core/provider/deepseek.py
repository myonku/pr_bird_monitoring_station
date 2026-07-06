from __future__ import annotations

from typing import Any

from openai import AsyncOpenAI
from openai import (
    APIConnectionError,
    APIStatusError,
    AuthenticationError,
    RateLimitError,
)

from src.agent_core.common.func import error_result
from src.iface.agent.providers import (
    ChatMessage,
    ChatResult,
    IChatProvider,
)
from src.models.agent.api import ChatRequest
from src.models.sys.config import AgentConfig


class DeepSeekChatProvider(IChatProvider):
    """基于 DeepSeek API 的真实 Chat 实现。

    使用 OpenAI-compatible AsyncOpenAI 客户端调用 DeepSeek 接口。
    配置通过 AgentConfig 注入（api_key / api_base / model 等）。
    """

    provider_name = "deepseek"

    def __init__(self, config: AgentConfig) -> None:
        if config is None:
            raise ValueError("config is required")

        self._config = config
        self._client = AsyncOpenAI(
            api_key=config.api_key,
            base_url=config.api_base,
        )

    async def generate(self, request: ChatRequest) -> ChatResult:
        messages = _build_openai_messages(request.messages)
        kwargs = _build_openai_kwargs(request, self._config)
        kwargs["messages"] = messages

        try:
            response = await self._client.chat.completions.create(**kwargs)
        except RateLimitError:
            return error_result(
                "PROVIDER_RATE_LIMIT",
                "deepseek rate limit exceeded",
                request,
                self._config,
                provider=self.provider_name,
            )
        except AuthenticationError:
            return error_result(
                "AUTH_FAILED",
                "deepseek authentication failed — check api_key",
                request,
                self._config,
                provider=self.provider_name,
            )
        except APIConnectionError:
            return error_result(
                "PROVIDER_UNAVAILABLE",
                "deepseek connection failed — check network or api_base",
                request,
                self._config,
                provider=self.provider_name,
            )
        except APIStatusError as exc:
            return error_result(
                "PROVIDER_UNAVAILABLE",
                f"deepseek api error (http {exc.status_code})",
                request,
                self._config,
                provider=self.provider_name,
            )
        except Exception as exc:
            return error_result(
                "INTERNAL_ERROR",
                f"deepseek unexpected error: {exc}",
                request,
                self._config,
                provider=self.provider_name,
            )

        choice = response.choices[0]
        return ChatResult(
            text=choice.message.content or "",
            raw=response.model_dump(),
            usage={
                "input_tokens": response.usage.prompt_tokens if response.usage else 0,
                "output_tokens": (
                    response.usage.completion_tokens if response.usage else 0
                ),
            },
            finish_reason=choice.finish_reason,
            provider=self.provider_name,
            model=response.model,
        )


def _build_openai_messages(messages: list[Any]) -> list[dict[str, Any]]:
    """将 ChatRequest.messages 转换为 OpenAI API 格式的 dict 列表。"""
    
    result: list[dict[str, Any]] = []
    for msg in messages:
        if isinstance(msg, ChatMessage):
            entry: dict[str, Any] = {
                "role": msg.role,
                "content": msg.content,
            }
            if msg.name:
                entry["name"] = msg.name
            result.append(entry)
        elif isinstance(msg, dict):
            result.append(msg)
    return result


def _build_openai_kwargs(
    request: ChatRequest,
    config: AgentConfig,
) -> dict[str, Any]:
    """从 ChatRequest + AgentConfig 组装 OpenAI API 请求参数。"""

    kwargs: dict[str, Any] = {
        "model": request.model or config.model,
        "temperature": (
            request.temperature
            if request.temperature is not None
            else config.temperature
        ),
        "max_tokens": request.max_tokens or config.max_tokens,
    }

    if request.response_format is not None:
        kwargs["response_format"] = request.response_format

    # DeepSeek 扩展参数（通过 request.metadata 传递）
    extra_body: dict[str, Any] = {}

    if request.metadata.get("enable_thinking"):
        extra_body["thinking"] = {"type": "enabled"}

    reasoning_effort = request.metadata.get("reasoning_effort")
    if reasoning_effort:
        kwargs["reasoning_effort"] = reasoning_effort

    if extra_body:
        kwargs["extra_body"] = extra_body

    kwargs["stream"] = False
    return kwargs
