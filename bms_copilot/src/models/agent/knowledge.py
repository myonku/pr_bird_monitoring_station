from __future__ import annotations


class KnowledgeDocument:
    """知识文档模型，记录知识的基本信息"""

    document_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    title: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None


class KnowledgeChunk:
    """知识块模型，记录知识的基本信息"""

    chunk_id: str
    document_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    content_type: str | None = None
    size_bytes: int | None = None


class EmbeddingVectorRef:
    """知识向量引用模型，记录知识向量的基本信息"""

    vector_id: str
    chunk_id: str
    document_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    dimension: int | None = None


class KnowledgeSourceVersion:
    """知识源版本模型，记录知识源的版本信息"""

    version_id: str
    source_id: str
    session_id: str
    user_id: str
    provider: str | None = None
    model: str | None = None
    version_number: int | None = None