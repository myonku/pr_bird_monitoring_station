"""SentenceEmbeddingProvider 快速验证脚本。"""

import asyncio
import os
import sys
from pathlib import Path

# 确保 src 可导入
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# 开发环境跳过 SSL 验证（首次需要从 HuggingFace 下载模型）
os.environ["HUGGINGFACE_HUB_DISABLE_SSL_VERIFY"] = "1"

from src.agent_core.provider.embedding_provider.sentence_tf import (
    SentenceEmbeddingProvider,
)
from src.models.agent.api import EmbeddingRequest


async def main():
    print("正在加载 model (首次需下载, 约 90MB)...")
    p = SentenceEmbeddingProvider()
    print(f"模型维度: {p._dimension}")

    result = await p.embed(EmbeddingRequest(texts=["hello world", "birds"]))
    print(f"向量数: {len(result.vectors)}")
    print(f"向量维度: {len(result.vectors[0])}")
    print(f"provider: {result.provider}")
    print("OK")


if __name__ == "__main__":
    asyncio.run(main())
