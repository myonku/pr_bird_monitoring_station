from typing import Any
from msgspec import Struct, field


class RetrievedChunk(Struct, kw_only=True):
    """检索到的知识块模型，包含知识块的基本信息和检索相关信息"""

    source_id: str
    title: str
    snippet: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)


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


class KnowledgeChunk(Struct, kw_only=True):
    """知识块模型：文档分块后的基本单元，最终存入向量库。"""

    chunk_id: str
    document_id: str
    text: str = ""
    title: str = ""
    species_id: str = ""
    vector_dimension: int = 0
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
