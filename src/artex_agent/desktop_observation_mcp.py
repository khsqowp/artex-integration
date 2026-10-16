"""Narrow Cowork MCP writer for one verified Juice Shop smoke observation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import uuid

from mcp.server.fastmcp import FastMCP

from .artex_api import ArtexClient
from .auth_store import get_admin_password


server = FastMCP("artex-observation-writer")
TASK_ID = 1
TASK_NAME = "artex-agent-smoke-test"
TARGET = "http://127.0.0.1:18081"
CONFIRMATION = "WRITE_OBSERVATION_TO_ARTEX_TASK_1"


def _authenticated_client() -> ArtexClient:
    password = get_admin_password()
    if not password:
        raise RuntimeError("ARTEx 자격 증명이 없습니다. 먼저 artex-auth-store를 실행하세요.")
    client = ArtexClient()
    client.login(password)
    return client


def _as_items(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("items", "tasks", "goals", "scope", "constraints", "data"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    return []


def _verify_context(client: ArtexClient) -> dict:
    task = client.get_task(TASK_ID)
    task_text = json.dumps(task, ensure_ascii=False, default=str)
    if TASK_NAME not in task_text:
        raise RuntimeError("ARTEx 작업 ID 1이 예상한 스모크 테스트 작업인지 확인할 수 없습니다.")

    scopes = _as_items(client.list_task_scope(TASK_ID))
    scope_text = json.dumps(scopes, ensure_ascii=False, default=str)
    if "127.0.0.1/32" not in scope_text and TARGET not in scope_text:
        raise RuntimeError("작업 범위에서 승인된 로컬 대상 항목을 확인하지 못했습니다.")

    constraints = _as_items(client.list_constraints(TASK_ID))
    allowed = False
    for item in constraints:
        rendered = json.dumps(item, ensure_ascii=False, default=str).lower()
        if TARGET in rendered and ("allow" in rendered or "허용" in rendered) and ("human" in rendered or "사람" in rendered):
            allowed = True
            break
    if not allowed:
        raise RuntimeError("작업 제약에서 해당 URL의 사람 승인 allow 항목을 확인하지 못했습니다.")
    return {"task": task, "scope": scopes, "constraints": constraints}


@server.tool()
def artex_record_smoke_observation(confirmation: str) -> str:
    """Record the already completed, read-only Juice Shop homepage check as an observation file.

    This does not contact the target or create a finding. To authorize the ARTEx
    workspace write, pass confirmation="WRITE_OBSERVATION_TO_ARTEX_TASK_1".
    """
    if confirmation != CONFIRMATION:
        raise ValueError(f"기록하려면 confirmation={CONFIRMATION!r}를 명시해야 합니다.")

    client = _authenticated_client()
    try:
        _verify_context(client)
        run_id = uuid.uuid4().hex[:12]
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        safe_stamp = re.sub(r"[^0-9T]", "", timestamp)
        path = f"tasks/{TASK_ID}/evidence/cowork-smoke-{safe_stamp}-{run_id}.md"
        content = f"""# 읽기 전용 연결 확인

- ARTEx 작업: {TASK_NAME} (ID {TASK_ID})
- 확인 시각(UTC): {timestamp}
- 승인 대상: {TARGET}
- 확인한 요청: `GET /` 문서 요청 1건
- 응답: `200`
- 페이지 제목: `OWASP Juice Shop`
- 최종 주소: `{TARGET}/#/`
- 제한: 로그인, 폼 제출, 취약점 테스트를 수행하지 않음
- 네트워크 범위: 문서 요청 1건은 확인했으나, 부수 리소스를 포함한 전체 요청 수는 미확인
- 분류: 관찰 기록이며 취약점 finding 또는 작업 완료 판정이 아님
- 범위 주의: ARTEx의 IP 범위 `127.0.0.1/32`는 포트를 제한하지 않으며, 이 기록은 작업 제약의 URL 승인과 함께 해석해야 함
"""
        write_result = client.write_workspace_file(path, content)
        read_result = client.read_workspace_file(path)
        saved = read_result.get("content") if isinstance(read_result, dict) else None
        if saved != content:
            raise RuntimeError("ARTEx 파일은 썼지만 재조회한 내용이 일치하지 않습니다.")
        return json.dumps({"ok": True, "task_id": TASK_ID, "path": path, "write": write_result,
                           "verified": True, "classification": "observation_not_finding"},
                          ensure_ascii=False, default=str)
    finally:
        client.clear_token()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
