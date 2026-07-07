from src.models.agent.api import ChatRequest
from src.iface.agent.providers import IChatProvider

from src.models.agent.api import ChatRequest, ChatResult


class AnthropicChatProvider(IChatProvider):
    provider_name = "anthropic"

    async def generate(self, request: ChatRequest) -> ChatResult:
        summary = " | ".join(message.role for message in request.messages)
        return ChatResult(
            text=f"[anthropic:{request.model}] roles={summary}",
            raw={"provider_request": request.to_dict()},
            usage={"input_tokens": len(request.messages), "output_tokens": 18},
            finish_reason="stop",
            provider=self.provider_name,
            model=request.model,
        )
