from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


PromptKind = Literal["system", "intent", "tool_router", "answer"]


@dataclass(slots=True)
class PromptTemplate:
    """prompt 协议样例。存放可版本化、可渲染、可组合的模板资产。
    """

    name: str
    kind: PromptKind
    version: str = "v1"
    description: str = ""
    template: str = ""
    variables: list[str] = field(default_factory=list)
    defaults: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def render(self, **kwargs: Any) -> str:
        values = dict(self.defaults)
        values.update(kwargs)
        return self.template.format_map(_SafeFormatDict(values))


class _SafeFormatDict(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"