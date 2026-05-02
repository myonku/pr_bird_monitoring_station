import asyncio
import logging
import random
from collections.abc import Callable, Awaitable
from typing import Any

import grpc
from etcd3aio import Etcd3Client
from msgspec import json

from src.models.common.instance import ServiceInstance
from src.models.sys.config import ProjectConfig
from src.utils.circuit_breaker import CircuitBreaker, CircuitOpenError

_log = logging.getLogger(__name__)


def _prefix_range_end(prefix: str) -> bytes:
    """计算 etcd Range 的 range_end 以实现前缀查询。

    方法：对最后一个字节 +1；若全 0xFF 则返回单字节 0x00 作为最小上界。
    参考 etcd 官方前缀范围约定。
    """
    b = bytearray(prefix.encode())
    for i in range(len(b) - 1, -1, -1):
        if b[i] < 0xFF:
            b[i] += 1
            return bytes(b[: i + 1])
    return b"\x00"


class EtcdAsyncClient:
    """原生异步 etcd v3 客户端（基于 etcd3aio/grpc.aio）

    仅实现本项目需要的最小接口：
      - connect
      - put_with_lease
      - keepalive_forever
      - delete
      - get_prefix
      - watch_prefix

    依赖: grpcio, etcd3aio。
    """

    def __init__(self, cfg: ProjectConfig) -> None:
        if not cfg.etcd:
            raise RuntimeError("Etcd配置初始化失败")
        if not cfg.etcd.HOSTS:
            raise RuntimeError("Etcd配置缺失HOSTS")

        self.cfg = cfg
        ns = (cfg.etcd.NAMESPACE or "").strip()
        ns = ns.strip("/")
        self.namespace = f"/{ns}" if ns else "/bms"

        # 针对 Etcd 的 RPC 维护一个熔断器
        self._circuit = CircuitBreaker("etcd_client", cfg.etcd.CIRCUITBREAKER)

        # 连接与 service 相关状态
        self._connected = False
        self._client: Etcd3Client | None = None
        self._kv_svc: Any | None = None
        self._lease_svc: Any | None = None
        self._watch_svc: Any | None = None
        self._lease_id: int | None = None

    async def connect(self):
        """建立 gRPC 连接并初始化服务 facade。"""
        etcd_cfg = self.cfg.etcd
        assert etcd_cfg and etcd_cfg.HOSTS, "Etcd 配置缺失 HOSTS"
        endpoints: list[str] = []
        for host_port in etcd_cfg.HOSTS:
            if ":" in host_port:
                endpoints.append(host_port)
            else:
                endpoints.append(f"{host_port}:2379")

        conn_args: dict[str, Any] = {}
        if etcd_cfg.TLS_ENABLED:
            root_bytes = None
            cert_chain_bytes = None
            key_bytes = None
            if etcd_cfg.CA_CERT:
                try:
                    with open(etcd_cfg.CA_CERT, "rb") as f:
                        root_bytes = f.read()
                except Exception:
                    root_bytes = None
            if etcd_cfg.CERT_FILE and etcd_cfg.KEY_FILE:
                try:
                    with open(etcd_cfg.CERT_FILE, "rb") as f:
                        cert_chain_bytes = f.read()
                    with open(etcd_cfg.KEY_FILE, "rb") as f:
                        key_bytes = f.read()
                except Exception:
                    cert_chain_bytes = None
                    key_bytes = None
            conn_args = {
                "ca_cert": root_bytes,
                "cert_chain": cert_chain_bytes,
                "cert_key": key_bytes,
            }

        self._client = Etcd3Client(endpoints=endpoints, **conn_args)
        await self._client.connect()
        self._kv_svc = self._client.kv
        self._lease_svc = self._client.lease
        self._watch_svc = self._client.watch
        assert self._kv_svc is not None
        assert self._lease_svc is not None
        assert self._watch_svc is not None
        self._connected = True

    async def _grant_or_reuse_lease(self, ttl: int) -> int:
        """创建或重用租约，返回租约 ID。"""
        if self._lease_id is not None:
            return self._lease_id
        assert self._lease_svc is not None, "Lease service 未初始化"

        async def _do_grant() -> Any:
            assert self._lease_svc is not None
            return await self._lease_svc.grant(ttl=ttl)

        try:
            resp = await self._circuit.call(_do_grant)
        except CircuitOpenError as e:
            # 熔断打开时直接抛出，调用方可决定是否降级
            raise e

        self._lease_id = resp.ID
        assert self._lease_id is not None
        return self._lease_id

    async def put_with_lease(self, key: str, value_bytes: bytes, ttl: int) -> None:
        """写入 key 并绑定租约（如不存在则创建新租约）。"""
        assert self._kv_svc is not None, "KV service 未初始化"
        lease_id = await self._grant_or_reuse_lease(ttl)

        async def _do_put() -> Any:
            assert self._kv_svc is not None
            return await self._kv_svc.put(key, value_bytes, lease=lease_id)

        await self._circuit.call(_do_put)

    async def put(self, key: str, value_bytes: bytes) -> None:
        """写入 key，不绑定租约。"""
        assert self._kv_svc is not None, "KV service 未初始化"

        async def _do_put() -> Any:
            assert self._kv_svc is not None
            return await self._kv_svc.put(key, value_bytes)

        await self._circuit.call(_do_put)

    async def keepalive_forever(self, ttl: int, stop_event: asyncio.Event):
        """保持租约存活（流式 keepalive）。"""
        if self._lease_id is None:
            return
        try:
            assert self._lease_svc is not None, "Lease service 未初始化"
            async with self._lease_svc.keep_alive_context(self._lease_id, ttl):
                await stop_event.wait()
        except Exception:
            _log.warning(
                "etcd keepalive_forever: keepalive 异常退出 (lease_id=%s, ttl=%s)",
                self._lease_id,
                ttl,
                exc_info=True,
            )

    async def delete(self, key: str):
        """删除指定 key。"""
        assert self._kv_svc is not None, "KV service 未初始化"

        async def _do_del() -> Any:
            assert self._kv_svc is not None
            return await self._kv_svc.delete(key)

        await self._circuit.call(_do_del)

    async def get_prefix(self, prefix: str) -> list[tuple[str, bytes]]:
        """列出前缀下所有 KV。"""
        assert self._kv_svc is not None, "KV service 未初始化"
        range_end = _prefix_range_end(prefix)

        async def _do_range() -> Any:
            assert self._kv_svc is not None
            return await self._kv_svc.get(prefix, range_end=range_end)

        resp = await self._circuit.call(_do_range)
        out: list[tuple[str, bytes]] = []
        for kv in resp.kvs:
            try:
                out.append((kv.key.decode(), kv.value))
            except Exception:
                continue
        return out

    async def get_prefix_with_revision(
        self, prefix: str
    ) -> tuple[int, list[tuple[str, bytes]]]:
        """返回 (etcd_revision, [(key,value_bytes)...])，用于避免加载与 watch 之间的竞态。"""
        assert self._kv_svc is not None, "KV service 未初始化"
        range_end = _prefix_range_end(prefix)

        async def _do_range() -> Any:
            assert self._kv_svc is not None
            return await self._kv_svc.get(prefix, range_end=range_end)

        resp = await self._circuit.call(_do_range)
        header = getattr(resp, "header", None)
        rev = int(getattr(header, "revision", 0) or 0)
        out: list[tuple[str, bytes]] = []
        for kv in resp.kvs:
            try:
                out.append((kv.key.decode(), kv.value))
            except Exception:
                continue
        return rev, out

    async def watch_prefix(
        self,
        prefix: str,
        callback: Callable[[str, bytes | None], Awaitable[None]],
        stop_event: asyncio.Event,
        start_revision: int = 0,
    ):
        """监听前缀，回调 put/delete 事件，并在断流/压缩后自恢复。

        start_revision: 指定起始修订（通常为 初始 Range 的 revision + 1）。
        """
        assert self._watch_svc is not None, "Watch service 未初始化"
        range_end = _prefix_range_end(prefix)

        next_revision: int = start_revision if start_revision > 0 else 0
        backoff = 0.2
        backoff_max = 5.0

        while not stop_event.is_set():
            try:
                stream = self._watch_svc.watch(
                    key=prefix.encode(),
                    range_end=range_end,
                    start_revision=next_revision if next_revision > 0 else 0,
                )
                backoff = 0.2
                async for resp in stream:
                    if stop_event.is_set():
                        break

                    # 压缩恢复
                    cr = int(getattr(resp, "compact_revision", 0) or 0)
                    if cr > 0 and (next_revision == 0 or next_revision <= cr):
                        next_revision = cr + 1
                        break

                    if getattr(resp, "canceled", False):
                        if cr > 0 and (next_revision == 0 or next_revision <= cr):
                            next_revision = cr + 1
                        break

                    for ev in getattr(resp, "events", []) or []:
                        etype = getattr(ev, "type", 0)
                        kv = getattr(ev, "kv", None)
                        if not kv:
                            continue
                        key_s = (
                            kv.key.decode()
                            if isinstance(kv.key, (bytes, bytearray))
                            else str(kv.key)
                        )
                        if etype == 0:
                            await callback(key_s, kv.value)
                        elif etype == 1:
                            await callback(key_s, None)

                        mr = int(getattr(kv, "mod_revision", 0) or 0)
                        if mr >= next_revision:
                            next_revision = mr + 1

            except grpc.aio.AioRpcError as e:
                code = e.code()
                if code not in (
                    grpc.StatusCode.UNAVAILABLE,
                    grpc.StatusCode.DEADLINE_EXCEEDED,
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                ):
                    _log.error(
                        "etcd watch_prefix: 不可恢复的 gRPC 错误 (%s)，退出监听",
                        code.name,
                        exc_info=True,
                    )
                    return
            except Exception:
                _log.error(
                    "etcd watch_prefix: 未预期的异常，退出监听", exc_info=True
                )
                return

            if stop_event.is_set():
                break
            await asyncio.sleep(backoff + random.random() * 0.2)
            backoff = min(backoff * 2, backoff_max)

    async def close(self):
        """关闭连接，释放资源。"""
        if self._client is not None:
            await self._client.close()
        self._connected = False
        self._lease_id = None
        self._client = None
        self._kv_svc = None
        self._lease_svc = None
        self._watch_svc = None


def build_service_key(ns: str, name: str, instance_id: str) -> str:
    """生成服务实例的 etcd 键"""
    namespace = _normalize_namespace(ns)
    return f"{namespace}/services/{name}/{instance_id}"


def build_prefix(ns: str, name: str) -> str:
    """生成服务前缀"""
    namespace = _normalize_namespace(ns)
    return f"{namespace}/services/{name}/"


def encode_instance(si: ServiceInstance) -> bytes:
    return json.encode(si)


def decode_instance(b: bytes) -> ServiceInstance:
    try:
        return json.decode(b, type=ServiceInstance)
    except Exception:
        payload = json.decode(b)
        if not isinstance(payload, dict):
            raise

        if "heartbeat" not in payload and "heartbeat_at" in payload:
            raw_hb = payload.get("heartbeat_at")
            if isinstance(raw_hb, (int, float)):
                heartbeat = int(raw_hb)
                if heartbeat < 10_000_000_000:
                    heartbeat *= 1000
                payload["heartbeat"] = heartbeat

        payload.setdefault("heartbeat", 0)
        payload.setdefault("zone", "")
        payload.setdefault("version", "")
        payload.setdefault("weight", 1)
        payload.setdefault("tags", [])
        payload.setdefault("active_comm_key_id", "")
        payload.setdefault("metadata", {})

        return json.decode(json.encode(payload), type=ServiceInstance)


def _normalize_namespace(ns: str) -> str:
    raw = (ns or "").strip().strip("/")
    return f"/{raw}" if raw else "/bms"
