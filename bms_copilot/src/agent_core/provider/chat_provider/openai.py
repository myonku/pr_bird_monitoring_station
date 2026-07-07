from src.models.agent.api import ChatRequest
from src.iface.agent.providers import IChatProvider

from src.models.agent.api import ChatRequest, ChatResult

class OpenAIChatProvider(IChatProvider):
    provider_name = "openai"

    async def generate(self, request: ChatRequest) -> ChatResult:
        combined_text = "\n".join(message.content for message in request.messages)
        return ChatResult(
            text=f"[openai:{request.model}] {combined_text[:200]}",
            raw={"provider_request": request.to_dict()},
            usage={"input_tokens": len(combined_text.split()), "output_tokens": 32},
            finish_reason="stop",
            provider=self.provider_name,
            model=request.model,
        )
