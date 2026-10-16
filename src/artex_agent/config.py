from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class LabTarget:
    base_url: str
    origin: str

    @classmethod
    def parse(cls, value: str) -> "LabTarget":
        parts = urlsplit(value.strip())
        if parts.scheme != "http":
            raise ValueError("첫 프로토타입은 로컬 Juice Shop의 HTTP 주소만 허용합니다.")
        if parts.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("대상은 이 컴퓨터의 localhost 또는 127.0.0.1만 허용합니다.")
        if parts.port != 18081:
            raise ValueError("허용된 Juice Shop 포트는 18081입니다.")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("인증 정보, 쿼리, 프래그먼트가 포함된 주소는 허용하지 않습니다.")

        origin = f"http://{parts.netloc}"
        base_url = origin + (parts.path or "/")
        if not base_url.endswith("/"):
            base_url += "/"
        return cls(base_url=base_url, origin=origin)

