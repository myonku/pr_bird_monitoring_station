from __future__ import annotations

from typing import Any

from msgspec import Struct, field


class KnowledgeDocument(Struct):
    """知识文档模型，记录知识的基本信息"""

    document_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    title: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class KnowledgeChunk(Struct):
    """知识块模型，记录知识的基本信息"""

    chunk_id: str
    document_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class EmbeddingVectorRef(Struct):
    """知识向量引用模型，记录知识向量的基本信息"""

    vector_id: str
    chunk_id: str
    document_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    dimension: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class KnowledgeSourceVersion(Struct):
    """知识源版本模型，记录知识源的版本信息"""

    version_id: str
    source_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    version_number: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
