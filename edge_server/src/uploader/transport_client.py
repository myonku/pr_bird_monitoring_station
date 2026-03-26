from __future__ import annotations

import base64
import json
from urllib import request
from urllib.error import HTTPError, URLError

from src.interface import IHttpTransportClient


class HttpTransportClient(IHttpTransportClient):
    """HTTP 传输客户端，统一负责上传与健康检查。"""

    def __init__(
        self,
        upload_url: str,
        healthcheck_url: str,
        timeout_sec: float = 3.0,
        auth_token: str | None = None,
    ) -> None:
        self.upload_url = upload_url
        self.healthcheck_url = healthcheck_url
        self.timeout_sec = timeout_sec
        self.auth_token = auth_token

    def send(self, payload: dict, image_bytes: bytes) -> bool:
        body = {
            **payload,
            "image_b64": base64.b64encode(image_bytes).decode("ascii"),
        }
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        req = request.Request(
            self.upload_url,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_sec) as resp:
                return 200 <= resp.status < 300
        except (HTTPError, URLError, TimeoutError):
            return False

    def healthcheck(self) -> bool:
        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        req = request.Request(self.healthcheck_url, headers=headers, method="GET")
        try:
            with request.urlopen(req, timeout=self.timeout_sec) as resp:
                return 200 <= resp.status < 300
        except (HTTPError, URLError, TimeoutError):
            return False