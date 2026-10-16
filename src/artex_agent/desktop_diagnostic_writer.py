"""Append-only ARTEx evidence and graph writer for the local assessment task.

Markdown evidence stays in the workspace. Separate graph tools append facts or
create confirmed findings through ARTEx's task-scoped native graph store.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import ipaddress
import re
import uuid
from typing import Annotated, Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .artex_api import ArtexClient
from .auth_store import get_admin_password


server = FastMCP("artex-diagnostic-writer")
TARGET = "http://127.0.0.1:18081"
CONFIRMATION = "WRITE_DIAGNOSTIC_EVIDENCE_TO_ARTEX"
MAX_FIELD_CHARS = 12_000
MAX_ASSETS_PER_WRITE = 20
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|authorization)\s*[:=]\s*\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
)


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


def _target_parts(target: str) -> tuple[str, str, str]:
    if not isinstance(target, str) or not target.strip() or len(target) > 2048:
        raise ValueError("target must be an HTTP(S) origin explicitly authorized by the task")
    parsed = urlsplit(target.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP(S) origin")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ValueError("target must be an origin only, without credentials, path, query, or fragment")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("target contains an invalid port") from exc
    host = parsed.hostname.rstrip(".").lower()
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return host, authority, f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _contains_authority(text: str, authority: str, origin: str) -> bool:
    lowered = text.lower()
    if origin in lowered:
        return True
    pattern = rf"(?<![a-z0-9.-]){re.escape(authority.lower())}(?![a-z0-9.-])"
    return re.search(pattern, lowered) is not None


def _scope_contains_target(scopes: list, host: str, authority: str, origin: str) -> bool:
    try:
        target_ip = ipaddress.ip_address(host)
    except ValueError:
        target_ip = None
    for item in scopes:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", "")).lower()
        values = [str(item.get(key, "")).strip() for key in ("value", "net", "cidr", "host", "domain", "url")]
        for value in filter(None, values):
            candidate = value.lower().rstrip(".")
            if candidate == host or candidate == authority.lower() or candidate == origin:
                return True
            try:
                network = ipaddress.ip_network(value, strict=False)
                if target_ip is not None and target_ip in network:
                    return True
            except ValueError:
                pass
            if kind in {"url", "endpoint"}:
                parsed = urlsplit(value)
                if parsed.hostname and parsed.hostname.rstrip(".").lower() == host:
                    if parsed.port is None or parsed.port == (443 if parsed.scheme == "https" else 80):
                        return True
    return False


def _verify_context(client: ArtexClient, task_id: int, target: str = TARGET) -> None:
    task = client.get_task(task_id)
    if not task:
        raise RuntimeError(f"ARTEx 작업 {task_id}을 찾을 수 없습니다.")

    raw_goals = client.list_goals(task_id)
    goals = _as_items(raw_goals)
    if not isinstance(raw_goals, (list, dict)):
        raise RuntimeError("ARTEx 목표 목록을 확인할 수 없어 쓰기를 거부했습니다.")
    if isinstance(raw_goals, dict) and not any(
        isinstance(raw_goals.get(key), list)
        for key in ("items", "goals", "data")
    ):
        raise RuntimeError("ARTEx 목표 응답 형식을 확인할 수 없어 쓰기를 거부했습니다.")
    # A goal-less task is not automatically read-only. ARTEx permits tasks
    # without goals, and the explicit scope + human allow/deny checks below are
    # the authorization boundary for appending Cowork records. When goals do
    # exist, reject explicitly read-only tasks and unrelated task objectives.
    if goals:
        goal_text = json.dumps(goals, ensure_ascii=False, default=str).lower()
        diagnostic_markers = (
            "진단", "취약점", "pentest", "침투 테스트", "보안 점검", "보안 진단",
            "공격 확인", "injection", "xss", "csrf", "디렉터리 인덱싱",
            "백업 및 임시파일", "중요정보 노출", "인증 우회",
        )
        if "읽기 전용" in goal_text or "read-only" in goal_text:
            raise RuntimeError("읽기 전용 ARTEx 작업에는 진단 기록을 저장할 수 없습니다.")
        if not any(term in goal_text for term in diagnostic_markers):
            raise RuntimeError("이 기록 도구는 진단 목표가 있는 작업 또는 목표가 비어 있고 승인된 범위가 확인된 작업에만 사용할 수 있습니다.")

    host, authority, origin = _target_parts(target)
    scopes = _as_items(client.list_task_scope(task_id))
    if not _scope_contains_target(scopes, host, authority, origin):
        raise RuntimeError("요청한 대상이 ARTEx 작업 범위에 포함되지 않습니다.")

    constraints = _as_items(client.list_constraints(task_id))
    matching_denies = []
    allowed = False
    for item in constraints:
        rendered = json.dumps(item, ensure_ascii=False, default=str).lower()
        kind = str(item.get("kind", "")).lower() if isinstance(item, dict) else ""
        source = str(item.get("source", "")).lower() if isinstance(item, dict) else ""
        text = str(item.get("text", "")) if isinstance(item, dict) else rendered
        matches_target = _contains_authority(text, authority, origin)
        if matches_target and (kind == "deny" or "deny" in rendered or "금지" in rendered or "거부" in rendered):
            matching_denies.append(text)
        if matches_target and (kind == "allow" or "allow" in rendered or "허용" in rendered) and (source == "human" or "human" in rendered or "사람" in rendered):
            allowed = True
    if matching_denies:
        raise RuntimeError("ARTEx 작업에 이 대상과 일치하는 deny 제약이 있어 기록을 거부했습니다.")
    if not allowed:
        raise RuntimeError("작업 제약에서 이 대상에 대한 사람 승인 allow를 확인하지 못했습니다.")


def _validate_task_assets(assets_json: str, target: str) -> list[dict]:
    """Accept only metadata for the exact authorized origin; never perform discovery."""
    if not isinstance(assets_json, str) or len(assets_json) > 48_000:
        raise ValueError("assets_json은 48000자 이하여야 합니다.")
    try:
        assets = json.loads(assets_json)
    except json.JSONDecodeError as exc:
        raise ValueError("assets_json은 JSON 배열이어야 합니다.") from exc
    if not isinstance(assets, list) or not 1 <= len(assets) <= MAX_ASSETS_PER_WRITE:
        raise ValueError(f"assets_json은 1~{MAX_ASSETS_PER_WRITE}개 자산의 배열이어야 합니다.")
    target_host, _, target_origin = _target_parts(target)
    target_parts = urlsplit(target_origin)
    allowed_fields = {
        "service": {"type", "url", "technologies", "status_code", "content_length", "page_title", "favicon_mmh3"},
        "endpoint": {"type", "url", "method"},
        "ip": {"type", "ip"},
    }
    normalized: list[dict] = []
    for index, item in enumerate(assets):
        if not isinstance(item, dict):
            raise ValueError(f"assets[{index}]은 객체여야 합니다.")
        asset_type = item.get("type")
        if asset_type not in allowed_fields:
            raise ValueError(f"assets[{index}].type은 service, endpoint, ip 중 하나여야 합니다.")
        unknown = set(item) - allowed_fields[asset_type]
        if unknown:
            raise ValueError(f"assets[{index}]에 지원하지 않는 필드가 있습니다: {', '.join(sorted(unknown))}")
        clean = {"type": asset_type}
        if asset_type == "ip":
            value = _clean_field(f"assets[{index}].ip", item.get("ip", ""))
            try:
                same_ip = ipaddress.ip_address(value) == ipaddress.ip_address(target_host)
            except ValueError:
                same_ip = False
            if not same_ip:
                raise ValueError(f"assets[{index}].ip must equal the approved target IP")
            clean["ip"] = value
        else:
            value = _clean_field(f"assets[{index}].url", item.get("url", ""))
            parts = urlsplit(value)
            try:
                same_origin = (
                    parts.scheme.lower() == target_parts.scheme.lower()
                    and (parts.hostname or "").rstrip(".").lower() == target_host
                    and (parts.port or (443 if parts.scheme.lower() == "https" else 80))
                    == (target_parts.port or (443 if target_parts.scheme.lower() == "https" else 80))
                    and not parts.username and not parts.password and not parts.query and not parts.fragment
                )
            except ValueError:
                same_origin = False
            if not same_origin:
                raise ValueError(f"assets[{index}].url must stay on the exact approved target origin")
            if asset_type == "service" and parts.path not in {"", "/"}:
                raise ValueError(f"assets[{index}] service URL must be the origin root")
            if asset_type == "endpoint" and any(part in {".", ".."} for part in parts.path.split("/")):
                raise ValueError(f"assets[{index}] endpoint path must not contain dot segments")
            clean["url"] = value
            if asset_type == "endpoint":
                method = _clean_field(f"assets[{index}].method", item.get("method", "")).upper()
                if method not in {"GET", "HEAD", "OPTIONS"}:
                    raise ValueError("endpoint metadata accepts only observed GET, HEAD, or OPTIONS methods")
                clean["method"] = method
            else:
                technologies = item.get("technologies", [])
                if not isinstance(technologies, list) or len(technologies) > 20:
                    raise ValueError("service technologies must be a list of at most 20 strings")
                clean["technologies"] = [_clean_field("technology", value)[:120] for value in technologies]
                if "status_code" in item:
                    status = item["status_code"]
                    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
                        raise ValueError("status_code must be an integer from 100 to 599")
                    clean["status_code"] = status
                if "content_length" in item:
                    length = item["content_length"]
                    if not isinstance(length, int) or isinstance(length, bool) or not 0 <= length <= 100_000_000:
                        raise ValueError("content_length must be an integer from 0 to 100000000")
                    clean["content_length"] = length
                if "page_title" in item:
                    clean["page_title"] = _clean_field("page_title", item["page_title"])[:500]
                if "favicon_mmh3" in item:
                    clean["favicon_mmh3"] = _clean_field("favicon_mmh3", item["favicon_mmh3"])[:120]
        normalized.append(clean)
    return normalized


def _collect_ids(value) -> set[int]:
    found: set[int] = set()
    if isinstance(value, dict):
        candidate = value.get("id")
        # ARTEx DTOs encode graph-node IDs as decimal strings, while a few
        # native writer responses and test doubles use integers.
        if isinstance(candidate, (int, str)) and not isinstance(candidate, bool):
            try:
                parsed = int(candidate)
            except (TypeError, ValueError):
                parsed = 0
            if parsed > 0:
                found.add(parsed)
        for nested in value.values():
            found.update(_collect_ids(nested))
    elif isinstance(value, list):
        for nested in value:
            found.update(_collect_ids(nested))
    return found


def _asset_readback_matches(surface, task_id: int, expected_by_id: dict[int, dict]) -> bool:
    """Verify each returned asset ID and every submitted field on the native task surface."""
    if not isinstance(surface, dict) or not isinstance(surface.get("assets"), list):
        return False
    rows = {
        row.get("id"): row
        for row in surface["assets"]
        if isinstance(row, dict) and isinstance(row.get("id"), int)
    }
    for asset_id, expected in expected_by_id.items():
        row = rows.get(asset_id)
        if not isinstance(row, dict) or task_id not in (row.get("task_ids") or []):
            return False
        if row.get("type") != expected.get("type"):
            return False
        field_map = {
            "ip": "ip", "url": "url", "method": "method",
            "technologies": "technologies", "status_code": "status_code",
            "content_length": "content_length", "page_title": "page_title",
            "favicon_mmh3": "favicon_mmh3",
        }
        for source, native in field_map.items():
            if source == "technologies" and expected.get(source) == [] and row.get(native) in (None, []):
                continue
            if source in expected and row.get(native) != expected[source]:
                return False
    return True


def _contains_record_id(value, *keys: str, expected: int) -> bool:
    """Find an ID in native ARTEx read-back payloads, including numeric strings."""
    if isinstance(value, dict):
        for key in keys:
            candidate = value.get(key)
            if candidate is not None and str(candidate) == str(expected):
                return True
        return any(_contains_record_id(item, *keys, expected=expected) for item in value.values())
    if isinstance(value, list):
        return any(_contains_record_id(item, *keys, expected=expected) for item in value)
    return False


def _graph_payload(node: dict) -> dict:
    payload = node.get("payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return {}
    return payload if isinstance(payload, dict) else {}


def _fact_readback_matches(records, node_id: int, summary: str, detail: str, evidence: str, confidence: str) -> bool:
    if not isinstance(records, dict) or not isinstance(records.get("facts"), list):
        return False
    node = next((
        item for item in records["facts"]
        if isinstance(item, dict) and str(item.get("id") or item.get("node_id")) == str(node_id)
    ), None)
    if not node or node.get("type") != "fact":
        return False
    payload = _graph_payload(node)
    return all(payload.get(key) == value for key, value in {
        "summary": summary, "detail": detail, "evidence": evidence, "confidence": confidence,
    }.items())


def _matching_fact_id(records, summary: str, detail: str, evidence: str, confidence: str) -> int | None:
    """Return an existing task-local fact ID for an exact payload match."""
    if not isinstance(records, dict) or not isinstance(records.get("facts"), list):
        return None
    matches = []
    for node in records["facts"]:
        if not isinstance(node, dict) or node.get("type") != "fact":
            continue
        payload = _graph_payload(node)
        if not all(payload.get(key) == value for key, value in {
            "summary": summary, "detail": detail, "evidence": evidence, "confidence": confidence,
        }.items()):
            continue
        try:
            node_id = int(node.get("id") or node.get("node_id") or 0)
        except (TypeError, ValueError):
            continue
        if node_id > 0:
            matches.append(node_id)
    return max(matches, default=None)


def _dashboard_record_matches(client: ArtexClient, task_id: int, summary: str) -> bool:
    """Verify the native Dashboard task row exposes the just-written record."""
    response = client.list_tasks()
    rows = response.get("tasks", []) if isinstance(response, dict) else []
    if not isinstance(rows, list):
        return False
    task = next((
        row for row in rows
        if isinstance(row, dict) and str(row.get("id") or row.get("task_id")) == str(task_id)
    ), None)
    if not task:
        return False
    visible_summary = task.get("latest_record_summary") or task.get("latest_fact_summary")
    try:
        visible_at = int(task.get("latest_record_unix") or 0)
    except (TypeError, ValueError):
        return False
    return visible_summary == summary and visible_at > 0


def _diagnostic_evidence_markdown(task_id: int, record_type: str, title: str, summary: str, evidence: str, target: str, timestamp: str, marker: str = "") -> str:
    prefix = f"{marker}\n" if marker else ""
    return (
        f"{prefix}# 진단 증거 기록: {title}\n\n"
        f"- ARTEx 작업 ID: {task_id}\n"
        f"- 기록 시각(UTC): {timestamp}\n"
        f"- 승인 대상: {target}\n"
        f"- 분류: `{record_type}`\n"
        f"- 공식 Finding 등록: 아니오\n"
        f"- ARTEx 그래프 fact: 연결 확인 진행 중\n"
        f"- 작업 상태 변경: 아니오\n\n"
        f"## 요약\n\n{summary}\n\n"
        f"## 근거 및 재현 정보\n\n{evidence}\n"
    )


def _find_session_activity(
    client: ArtexClient, task_id: int, session: str, predicate, *, expected_detail: str | None = None,
) -> bool:
    # A single small page can miss the just-written event if other Cowork or
    # ARTEx activity lands while a batch is being verified. Read newest-first
    # pages with a hard request cap; never scan the task's unbounded history.
    before = 0
    for _ in range(5):
        history = client.get_task_surface(
            task_id, "session_history", session=session, page=1, size=500, before=before,
        )
        if not isinstance(history, dict):
            return False
        items = history.get("items", [])
        for item in items:
            if not isinstance(item, dict) or not predicate(item):
                continue
            if expected_detail is None:
                return True
            # Session history intentionally omits the potentially large detail
            # blob. Fetch it only for the exact matched activity row, using its
            # task-scoped sequence ID, instead of weakening the write check or
            # loading details for every history item.
            try:
                seq = int(item.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            if seq <= 0:
                continue
            detail = client.get_activity_detail(task_id, seq)
            if isinstance(detail, dict) and detail.get("detail", "") == expected_detail:
                return True
        if not history.get("has_more"):
            return False
        try:
            cursor = int(history.get("earliest_cursor") or 0)
        except (TypeError, ValueError):
            return False
        if cursor <= 0 or cursor == before:
            return False
        before = cursor
    return False


def _verify_cowork_activity(client: ArtexClient, task_id: int, tool: str, tool_use_id: str) -> bool:
    return _find_session_activity(
        client, task_id, "cowork",
        lambda item: item.get("worker") == "cowork"
        and item.get("tool") == tool
        and item.get("tool_use_id") == tool_use_id,
    )


def _partial_write_result(task_id: int, operation: str, message: str, **details: Any) -> str:
    """Return an explicit no-blind-retry result after a write may have reached ARTEx."""
    return json.dumps({
        "ok": False,
        "verified": False,
        "partial_write": True,
        "native_record_verified": False,
        "activity_verified": False,
        "task_id": task_id,
        "operation": operation,
        "error": message,
        "retry_guidance": "쓰기 결과가 불확실합니다. 같은 작업을 재시도하기 전에 ARTEx Task 화면과 활동 이력을 확인하세요.",
        **details,
    }, ensure_ascii=False, default=str)


def _clean_field(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name}은(는) 비어 있을 수 없습니다.")
    value = value.strip()
    if len(value) > MAX_FIELD_CHARS:
        raise ValueError(f"{name} 길이가 {MAX_FIELD_CHARS}자를 초과합니다.")
    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        raise ValueError(f"{name}에 자격 증명처럼 보이는 문자열이 있어 저장을 거부했습니다.")
    return value


@server.tool()
def artex_record_diagnostic_evidence(
    task_id: int,
    record_type: str,
    title: str,
    summary: str,
    evidence: str,
    target: str,
    confirmation: str,
    checkpoint_id: str = "",
) -> str:
    """Save one evidence file and linked graph fact after validating this task's scope and human allow.

    record_type must be observation, candidate, or finding_evidence. Even
    finding_evidence is not a formal ARTEx finding. The matching graph fact makes
    the checkpoint visible in Records, Exploration, Broadcast, and Dashboard.
    Success includes rereading the task row's latest-record summary from ARTEx;
    if Dashboard does not expose the same record, the result is partial_write.
    This tool never contacts the test target or changes task status.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id는 양의 정수여야 합니다.")
    if confirmation != CONFIRMATION:
        raise ValueError(f"기록하려면 confirmation={CONFIRMATION!r}를 명시해야 합니다.")
    if record_type not in {"observation", "candidate", "finding_evidence"}:
        raise ValueError("record_type은 observation, candidate, finding_evidence 중 하나여야 합니다.")
    title = _clean_field("title", title)
    summary = _clean_field("summary", summary)
    evidence = _clean_field("evidence", evidence)
    if not isinstance(checkpoint_id, str):
        raise ValueError("checkpoint_id는 문자열이어야 합니다.")
    checkpoint_id = checkpoint_id.strip()
    if checkpoint_id and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", checkpoint_id):
        raise ValueError("checkpoint_id는 영문/숫자로 시작하는 1~64자 식별자여야 합니다.")

    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        fact_summary = title[:MAX_FIELD_CHARS]
        fact_detail = f"{record_type}: {summary}"[:MAX_FIELD_CHARS]
        confidence = "inferred" if record_type == "candidate" else "observed"
        if checkpoint_id:
            digest = hashlib.sha256(json.dumps(
                [task_id, record_type, title, summary, evidence, target], ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            marker = f"<!-- artex-checkpoint-sha256:{digest} -->"
            path = f"tasks/{task_id}/evidence/cowork-diagnostic-{checkpoint_id}.md"
            try:
                records_before = client.get_task_surface(task_id, "records")
            except Exception as exc:
                return _partial_write_result(task_id, "record_diagnostic_evidence", f"체크포인트 재시도 확인 실패: {type(exc).__name__}", path=path, workspace_file_verified=False, formal_finding_created=False)
            if (
                not isinstance(records_before, dict)
                or records_before.get("facts_error")
                or records_before.get("files_error")
                or not isinstance(records_before.get("facts"), list)
                or not isinstance(records_before.get("files"), list)
            ):
                return _partial_write_result(task_id, "record_diagnostic_evidence", "체크포인트 재시도 전 Task Records를 완전히 읽지 못했습니다.", path=path, workspace_file_verified=False, formal_finding_created=False)
            file_rows = records_before["files"]
            existing_file = any(
                isinstance(row, dict) and row.get("path") == path
                for row in file_rows
            )
            if existing_file:
                try:
                    prior = client.read_task_workspace_file(task_id, path)
                except Exception as exc:
                    return _partial_write_result(task_id, "record_diagnostic_evidence", f"기존 체크포인트 파일을 읽지 못했습니다: {type(exc).__name__}", path=path, workspace_file_verified=False, formal_finding_created=False)
                content = prior.get("content") if isinstance(prior, dict) else None
                timestamp_match = re.search(r"(?m)^- 기록 시각\(UTC\): (.+)$", content or "")
                expected_pending = _diagnostic_evidence_markdown(
                    task_id, record_type, title, summary, evidence, target,
                    timestamp_match.group(1) if timestamp_match else "", marker,
                )
                normalized_prior = re.sub(
                    r"(?m)^- ARTEx 그래프 fact: #[1-9][0-9]*$",
                    "- ARTEx 그래프 fact: 연결 확인 진행 중", content or "", count=1,
                )
                if not isinstance(content, str) or marker not in content or normalized_prior != expected_pending:
                    return _partial_write_result(task_id, "record_diagnostic_evidence", "같은 checkpoint_id에 다른 내용의 파일이 있어 덮어쓰기를 거부했습니다.", path=path, workspace_file_verified=False, formal_finding_created=False)
                write_result = {"ok": True, "reused": True}
            else:
                timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
                content = _diagnostic_evidence_markdown(task_id, record_type, title, summary, evidence, target, timestamp, marker)
                try:
                    write_result = client.write_workspace_file(path, content)
                except Exception as exc:
                    return _partial_write_result(task_id, "record_diagnostic_evidence", f"증거 파일 저장 실패: {type(exc).__name__}", path=path, workspace_file_verified=False, formal_finding_created=False)
        else:
            timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
            stamp = re.sub(r"[^0-9T]", "", timestamp)
            run_id = uuid.uuid4().hex[:12]
            path = f"tasks/{task_id}/evidence/cowork-diagnostic-{stamp}-{run_id}.md"
            content = _diagnostic_evidence_markdown(task_id, record_type, title, summary, evidence, target, timestamp)
            try:
                write_result = client.write_workspace_file(path, content)
            except Exception as exc:
                return _partial_write_result(task_id, "record_diagnostic_evidence", f"증거 파일 저장 실패: {type(exc).__name__}", path=path, workspace_file_verified=False, formal_finding_created=False)
        try:
            read_result = client.read_task_workspace_file(task_id, path)
        except Exception as exc:
            return _partial_write_result(task_id, "record_diagnostic_evidence", f"증거 파일 쓰기/재조회 결과를 확인하지 못했습니다: {type(exc).__name__}", path=path, workspace_file_verified=False, formal_finding_created=False)
        saved = read_result.get("content") if isinstance(read_result, dict) else None
        if saved != content:
            return _partial_write_result(task_id, "record_diagnostic_evidence", "증거 파일은 저장 요청됐지만 재조회 내용이 일치하지 않습니다.", path=path, workspace_file_verified=False, formal_finding_created=False)
        fact_evidence = f"Supporting workspace evidence: {path}"
        graph_fact_verified = False
        workspace_file_finalized = False
        activity_verified = False
        dashboard_record_verified = False
        try:
            fact_result = None
            records = client.get_task_surface(task_id, "records")
            node_id = _matching_fact_id(records, fact_summary, fact_detail, fact_evidence, confidence)
            idempotent_reuse = node_id is not None
            if node_id is None:
                fact_result = client.record_task_fact(
                    task_id, fact_summary, fact_detail, fact_evidence, confidence,
                    target, f"CONFIRM record_fact task={task_id}",
                )
                if not isinstance(fact_result, dict) or not fact_result.get("ok") or not fact_result.get("node_id"):
                    raise RuntimeError("ARTEx가 연결 graph fact ID를 반환하지 않았습니다.")
                node_id = int(fact_result["node_id"])
                records = client.get_task_surface(task_id, "records")
            if not _fact_readback_matches(records, node_id, fact_summary, fact_detail, fact_evidence, confidence):
                raise RuntimeError("workspace 파일은 저장됐지만 연결 graph fact의 Task Records 재조회가 일치하지 않습니다.")
            graph_fact_verified = True
            finalized_content = re.sub(r"(?m)^- ARTEx 그래프 fact: .*?$", f"- ARTEx 그래프 fact: #{node_id}", content, count=1)
            if finalized_content != content:
                client.write_workspace_file(path, finalized_content)
                finalized = client.read_task_workspace_file(task_id, path)
                if not isinstance(finalized, dict) or finalized.get("content") != finalized_content:
                    raise RuntimeError("graph fact는 확인됐지만 파일에 fact ID를 반영한 최종 재조회가 일치하지 않습니다.")
                content = finalized_content
            workspace_file_finalized = True
            activity_verified = _verify_cowork_activity(client, task_id, "record_fact", f"cowork-fact-{node_id}")
            if not activity_verified:
                raise RuntimeError("workspace 파일과 graph fact는 저장됐지만 Cowork 활동 이력을 확인하지 못했습니다.")
            dashboard_record_verified = _dashboard_record_matches(client, task_id, fact_summary)
            if not dashboard_record_verified:
                raise RuntimeError("workspace 파일, graph fact, 활동 이력은 확인됐지만 Dashboard의 최근 기록 행에서 같은 기록을 확인하지 못했습니다.")
        except Exception as exc:
            return json.dumps({
                "ok": False, "verified": False, "partial_write": True,
                "task_id": task_id, "path": path, "workspace_file_verified": True,
                "workspace_file_finalized": workspace_file_finalized,
                "node_id": node_id if "node_id" in locals() else (fact_result.get("node_id") if isinstance(fact_result, dict) else None),
                "graph_fact_verified": graph_fact_verified,
                "activity_verified": activity_verified,
                "dashboard_record_verified": dashboard_record_verified,
                # Exception text may contain request paths, response fragments,
                # or other server details. Keep the tool result safe to echo.
                "error": f"ARTEx fact write/readback failed: {type(exc).__name__}",
                "formal_finding_created": False,
            }, ensure_ascii=False, default=str)
        return json.dumps({
            "ok": True,
            "task_id": task_id,
            "target": target,
            "path": path,
            "node_id": node_id,
            "write": write_result,
            "verified": True,
            "workspace_file_verified": True,
            "workspace_file_finalized": True,
            "graph_fact_verified": True,
            "activity_verified": True,
            "dashboard_record_verified": True,
            "visible_surfaces": ["records", "exploration", "broadcast", "dashboard"],
            "classification": record_type,
            "idempotent_reuse": idempotent_reuse,
            "formal_finding_created": False,
        }, ensure_ascii=False, default=str)
    finally:
        client.clear_token()


@server.tool()
def artex_save_task_report(
    task_id: Annotated[int, Field(description="Positive ARTEx task ID. Saves only this task's report.")],
    report: Annotated[str, Field(description="Markdown report text. Synthetic acceptance reports must be clearly labeled; do not include credentials or personal data.")],
    target: Annotated[str, Field(description="Required HTTP(S) ORIGIN matching this task's scope and human allow; no path/query. Authorization metadata only; this tool sends no target request.")],
    confirmation: Annotated[str, Field(description="Exact operation confirmation: CONFIRM save_task_report task=<task_id>.")],
) -> str:
    """Save a reviewed Cowork-authored Task report for ARTEx's Report tab.

    This writes a fixed task-owned Markdown path, links it from a graph fact,
    and verifies both records. It does not overwrite ARTEx finding reports.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id는 양의 정수여야 합니다.")
    expected = f"CONFIRM save_task_report task={task_id}"
    if confirmation != expected:
        raise ValueError(f"보고서 저장에는 confirmation={expected!r}가 필요합니다.")
    if not isinstance(report, str) or not report.strip() or len(report) > 120_000:
        raise ValueError("report는 비어 있지 않고 120000자 이하여야 합니다.")
    report = report.strip()
    if any(pattern.search(report) for pattern in SECRET_PATTERNS):
        raise ValueError("report에 자격 증명처럼 보이는 문자열이 있어 저장을 거부했습니다.")
    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        digest = hashlib.sha256(report.encode("utf-8")).hexdigest()
        summary = "Cowork 보고서 저장"
        detail = f"Reviewed report sha256={digest}"
        evidence = f"Task report artifact: tasks/{task_id}/reports/cowork-report.md"
        confidence = "inferred"
        path = f"tasks/{task_id}/reports/cowork-report.md"
        marker = "<!-- cowork-report-content -->"

        # Successful retries reuse the already linked fact; a prior partial
        # write also remains discoverable by its deterministic report digest.
        existing_content = ""
        try:
            existing = client.read_task_workspace_file(task_id, path)
            if isinstance(existing, dict) and isinstance(existing.get("content"), str):
                existing_content = existing["content"]
        except Exception as exc:
            message = str(exc)
            if "HTTP 404" not in message and "文件不存在" not in message:
                return _partial_write_result(task_id, "save_task_report", f"기존 보고서 확인에 실패했습니다: {type(exc).__name__}", report_path=path, report_verified=False)

        try:
            records = client.get_task_surface(task_id, "records")
        except Exception as exc:
            return _partial_write_result(task_id, "save_task_report", f"중복 확인용 Task Records 조회에 실패했습니다: {type(exc).__name__}", report_path=path, report_verified=bool(existing_content))
        existing_fact_id = _matching_fact_id(records, summary, detail, evidence, confidence)
        if existing_fact_id is not None:
            old_body = existing_content.split(marker, 1)[1].strip() if marker in existing_content else None
            old_node = re.search(r"(?m)^- ARTEx 그래프 fact: #([1-9][0-9]*)\s*$", existing_content)
            same_target = f"- 승인 대상: {target}" in existing_content
            if old_body == report and old_node and int(old_node.group(1)) == existing_fact_id and same_target:
                try:
                    activity_verified = _verify_cowork_activity(client, task_id, "record_fact", f"cowork-fact-{existing_fact_id}")
                except Exception:
                    activity_verified = False
                if activity_verified:
                    return json.dumps({
                        "ok": True, "verified": True, "task_id": task_id,
                        "report_path": path, "node_id": existing_fact_id,
                        "activity_verified": True, "idempotent_reuse": True,
                        "visible_surface": "task_report",
                    }, ensure_ascii=False, default=str)

        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        content = (
            f"# Cowork Task Report\n\n"
            f"- ARTEx task: {task_id}\n- 작성 시각(UTC): {timestamp}\n"
            f"- 승인 대상: {target}\n- 작성 런타임: Claude Cowork\n"
            f"- Report SHA-256: {digest}\n"
            f"- ARTEx 그래프 fact: 연결 확인 진행 중\n\n{marker}\n{report}\n"
        )
        try:
            write_result = client.write_workspace_file(path, content)
            saved = client.read_task_workspace_file(task_id, path)
        except Exception as exc:
            return _partial_write_result(task_id, "save_task_report", f"보고서 파일 쓰기/재조회 결과를 확인하지 못했습니다: {type(exc).__name__}", report_path=path, report_verified=False)
        if not isinstance(saved, dict) or saved.get("content") != content:
            return _partial_write_result(task_id, "save_task_report", "보고서는 저장 요청됐지만 Task 소유 경로에서 내용을 확인하지 못했습니다.", report_path=path, report_verified=False)
        fact_reused = existing_fact_id is not None
        fact_result = {"ok": True, "node_id": existing_fact_id, "activity_updated": True} if fact_reused else None
        if not fact_reused:
            try:
                fact_result = client.record_task_fact(
                    task_id, summary, detail, evidence, confidence, target,
                    f"CONFIRM record_fact task={task_id}",
                )
            except Exception as exc:
                return _partial_write_result(task_id, "save_task_report", f"보고서는 확인됐지만 연결 fact 쓰기 응답을 확인하지 못했습니다: {type(exc).__name__}", report_path=path, report_verified=True, graph_fact_verified=False)
        if not isinstance(fact_result, dict) or not fact_result.get("ok") or not fact_result.get("node_id"):
            return json.dumps({"ok": False, "verified": False, "partial_write": True, "task_id": task_id, "report_path": path, "report_verified": True, "graph_fact_verified": False, "error": "보고서는 저장됐지만 ARTEx가 연결 fact ID를 반환하지 않았습니다."}, ensure_ascii=False, default=str)
        try:
            node_id = int(fact_result["node_id"])
        except (TypeError, ValueError):
            return _partial_write_result(task_id, "save_task_report", "보고서는 저장됐지만 연결 fact ID가 유효하지 않습니다.", report_path=path, report_verified=True)
        try:
            records = client.get_task_surface(task_id, "records")
        except Exception as exc:
            return _partial_write_result(task_id, "save_task_report", f"보고서와 fact가 쓰였지만 Task Records 재조회에 실패했습니다: {type(exc).__name__}", report_path=path, node_id=node_id, report_verified=True)
        if not _fact_readback_matches(records, node_id, summary, detail, evidence, confidence):
            return json.dumps({"ok": False, "verified": False, "partial_write": True, "task_id": task_id, "report_path": path, "node_id": node_id, "report_verified": True, "graph_fact_verified": False, "error": "보고서는 저장됐지만 연결 fact의 재조회가 일치하지 않습니다."}, ensure_ascii=False, default=str)
        content = content.replace(
            "- ARTEx 그래프 fact: 연결 확인 진행 중\n",
            f"- ARTEx 그래프 fact: #{node_id}\n",
            1,
        )
        try:
            client.write_workspace_file(path, content)
            finalized = client.read_task_workspace_file(task_id, path)
        except Exception as exc:
            return _partial_write_result(task_id, "save_task_report", f"fact 연결 정보가 있는 최종 보고서 재조회에 실패했습니다: {type(exc).__name__}", report_path=path, node_id=node_id, report_verified=False, graph_fact_verified=True)
        if not isinstance(finalized, dict) or finalized.get("content") != content:
            return json.dumps({"ok": False, "verified": False, "partial_write": True, "task_id": task_id, "report_path": path, "node_id": node_id, "report_verified": False, "graph_fact_verified": True, "error": "graph fact는 확인됐지만 보고서 파일에 fact ID를 반영한 최종 재조회가 일치하지 않습니다."}, ensure_ascii=False, default=str)
        try:
            activity_verified = (fact_reused or bool(fact_result.get("activity_updated"))) and _verify_cowork_activity(client, task_id, "record_fact", f"cowork-fact-{node_id}")
        except Exception:
            activity_verified = False
        if not activity_verified:
            return json.dumps({"ok": False, "verified": False, "partial_write": True, "task_id": task_id, "report_path": path, "node_id": node_id, "report_verified": True, "graph_fact_verified": True, "activity_verified": False, "error": "보고서와 graph fact는 저장됐지만 Cowork 활동 이력을 확인하지 못했습니다."}, ensure_ascii=False, default=str)
        return json.dumps({"ok": True, "verified": True, "task_id": task_id, "report_path": path, "node_id": node_id, "activity_verified": True, "visible_surface": "task_report", "idempotent_reuse": fact_reused, "write": write_result}, ensure_ascii=False, default=str)
    finally:
        client.clear_token()


@server.tool()
def artex_record_task_fact(
    task_id: Annotated[int, Field(description="Positive ARTEx task ID. Use only the explicitly selected task.")],
    summary: Annotated[str, Field(description="Short synthetic or evidence-grounded fact title. Never put secrets here.")],
    detail: Annotated[str, Field(description="Fact detail. Distinguish direct observation from inference; do not claim unverified results.")],
    evidence: Annotated[str, Field(description="Supporting evidence or explicit synthetic-test explanation. Do not include credentials, cookies, tokens, or personal data.")],
    confidence: Annotated[str, Field(description="Required enum: 'observed' or 'inferred'. Use 'observed' only for directly verified data; synthetic acceptance records should be explicitly identified in the text.")],
    target: Annotated[str, Field(description="Required HTTP(S) ORIGIN (scheme + host + optional port, no path/query). Must match this task's scope and human allow. This is authorization metadata; this tool sends no target request.")],
    confirmation: Annotated[str, Field(description="Exact operation confirmation: CONFIRM record_fact task=<task_id>.")],
) -> str:
    """Append one observation/conclusion to the task exploration graph.

    This appears in the task graph and updates task activity/dashboard recency;
    success includes a readback of the Dashboard task-row summary.
    It never creates a formal finding or sends requests to the assessment target.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id는 양의 정수여야 합니다.")
    expected = f"CONFIRM record_fact task={task_id}"
    if confirmation != expected:
        raise ValueError(f"기록하려면 confirmation={expected!r}가 필요합니다.")
    summary = _clean_field("summary", summary)
    detail = _clean_field("detail", detail)
    evidence = _clean_field("evidence", evidence)
    if confidence not in {"observed", "inferred"}:
        raise ValueError("confidence는 observed 또는 inferred여야 합니다.")
    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        try:
            result = client.record_task_fact(task_id, summary, detail, evidence, confidence, target, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "record_fact", f"ARTEx 쓰기 응답을 확인하지 못했습니다: {type(exc).__name__}")
        if not isinstance(result, dict) or not result.get("ok") or not result.get("node_id"):
            return _partial_write_result(task_id, "record_fact", "ARTEx가 사실 노드 생성 ID를 반환하지 않았습니다.")
        try:
            fact_node_id = int(result["node_id"])
        except (TypeError, ValueError):
            return _partial_write_result(task_id, "record_fact", "ARTEx가 유효한 사실 노드 ID를 반환하지 않았습니다.")
        try:
            records = client.get_task_surface(task_id, "records")
        except Exception as exc:
            return _partial_write_result(task_id, "record_fact", f"사실 노드는 반환됐지만 Task Records 재조회에 실패했습니다: {type(exc).__name__}", node_id=fact_node_id)
        if not _fact_readback_matches(records, fact_node_id, summary, detail, evidence, confidence):
            return _partial_write_result(task_id, "record_fact", "사실 노드는 반환됐지만 Task Records의 저장 내용이 일치하지 않습니다.", node_id=fact_node_id)
        try:
            activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(
                client, task_id, "record_fact", f"cowork-fact-{fact_node_id}"
            )
        except Exception as exc:
            return _partial_write_result(task_id, "record_fact", f"사실은 저장됐지만 Cowork 활동 이력 재조회에 실패했습니다: {type(exc).__name__}", node_id=fact_node_id, native_record_verified=True)
        if not activity_verified:
            return _partial_write_result(task_id, "record_fact", "사실은 저장됐지만 Cowork 활동 이력에서 기록을 확인하지 못했습니다.", node_id=fact_node_id, native_record_verified=True)
        try:
            dashboard_record_verified = _dashboard_record_matches(client, task_id, summary)
        except Exception as exc:
            return _partial_write_result(task_id, "record_fact", f"사실과 활동은 확인됐지만 Dashboard 재조회에 실패했습니다: {type(exc).__name__}", node_id=fact_node_id, native_record_verified=True, activity_verified=True)
        if not dashboard_record_verified:
            return _partial_write_result(task_id, "record_fact", "사실과 활동은 확인됐지만 Dashboard 최근 기록에서 같은 사실을 확인하지 못했습니다.", node_id=fact_node_id, native_record_verified=True, activity_verified=True, dashboard_record_verified=False)
        return json.dumps({"ok": True, "verified": True, "native_record_verified": True, "task_id": task_id, "node_id": result["node_id"], "kind": "fact", "formal_finding_created": False, "activity_updated": True, "activity_verified": True, "dashboard_record_verified": True, "partial_write": False}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_prove_goal(
    task_id: int,
    goal_id: int,
    evidence_id: int,
    target: str,
    reason: str,
    confirmation: str,
) -> str:
    """Mark one ARTEx goal met using an existing same-task fact or confirmed finding.

    The evidence must already be recorded in the task graph. Completing the last
    open goal marks the native ARTEx task done. Never use this for incomplete or
    inferred coverage.
    """
    if not isinstance(task_id, int) or task_id <= 0 or not isinstance(goal_id, int) or goal_id <= 0 or not isinstance(evidence_id, int) or evidence_id <= 0:
        raise ValueError("task_id, goal_id and evidence_id must be positive integers")
    expected = f"CONFIRM prove_goal task={task_id} goal={goal_id} evidence={evidence_id}"
    if confirmation != expected:
        raise ValueError(f"목표 달성 기록에는 confirmation={expected!r}가 필요합니다.")
    reason = _clean_field("reason", reason)
    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        try:
            result = client.prove_task_goal(task_id, goal_id, evidence_id, target, reason, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "prove_goal", f"목표 증명 응답을 확인하지 못했습니다: {type(exc).__name__}", goal_id=goal_id, evidence_id=evidence_id)
        try:
            result_matches_request = (
                isinstance(result, dict)
                and result.get("ok")
                and int(result.get("goal_id", 0)) == goal_id
                and int(result.get("evidence_id", 0)) == evidence_id
            )
        except (TypeError, ValueError):
            result_matches_request = False
        if not result_matches_request:
            return _partial_write_result(task_id, "prove_goal", "ARTEx가 목표 증명 결과를 확인하지 못했습니다.", goal_id=goal_id, evidence_id=evidence_id)
        try:
            goals = _as_items(client.list_goals(task_id))
        except Exception as exc:
            return _partial_write_result(task_id, "prove_goal", f"목표 증명 응답은 받았지만 목표 목록 재조회에 실패했습니다: {type(exc).__name__}", goal_id=goal_id, evidence_id=evidence_id)
        saved_goal = next((item for item in goals if isinstance(item, dict) and str(item.get("id")) == str(goal_id)), None)
        if not saved_goal or saved_goal.get("state") != "met":
            return _partial_write_result(task_id, "prove_goal", "목표 증명 응답은 받았지만 ARTEx 목표 목록에서 met 상태를 확인하지 못했습니다.", goal_id=goal_id, evidence_id=evidence_id)
        activity_id = f"cowork-prove-goal-{goal_id}-{evidence_id}"
        try:
            activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(client, task_id, "prove_goal", activity_id)
        except Exception:
            activity_verified = False
        if not activity_verified:
            return _partial_write_result(
                task_id,
                "prove_goal",
                "목표는 met으로 확인됐지만 Cowork 활동 이력을 확인하지 못했습니다. 재시도 전에 Task 화면을 확인하세요.",
                goal_id=goal_id,
                evidence_id=evidence_id,
                state="met",
                native_record_verified=True,
                task_completed=bool(result.get("task_completed")),
            )
        return json.dumps({
            "ok": True,
            "verified": True,
            "native_record_verified": True,
            "task_id": task_id,
            "goal_id": goal_id,
            "evidence_id": evidence_id,
            "state": "met",
            "task_completed": bool(result.get("task_completed")),
            "surface": "overview_and_exploration_graph",
            "activity_updated": bool(result.get("activity_updated")),
            "activity_verified": activity_verified,
            "partial_write": False,
        }, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_pause_task(task_id: int, confirmation: str) -> str:
    """Pause ARTEx's native planner/worker execution after an explicit operator request.

    This does not pause the current Claude Cowork session. There is deliberately
    no resume tool here because resuming would start ARTEx's separate LLM engine.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id must be a positive integer")
    expected = f"CONFIRM pause_task task={task_id}"
    if confirmation != expected:
        raise ValueError(f"일시정지에는 confirmation={expected!r}가 필요합니다.")
    client = _authenticated_client()
    try:
        before = client.get_task(task_id)
        if not isinstance(before, dict):
            raise RuntimeError("ARTEx task 상태를 확인하지 못했습니다.")
        already_paused = bool(before.get("paused"))
        if already_paused:
            result = {"ok": True, "activity_updated": False}
        else:
            try:
                result = client.pause_task(task_id, confirmation)
            except Exception as exc:
                return _partial_write_result(task_id, "pause_task", f"일시정지 응답을 확인하지 못했습니다: {type(exc).__name__}")
        try:
            task = client.get_task(task_id)
        except Exception as exc:
            return _partial_write_result(task_id, "pause_task", f"일시정지 응답은 받았지만 task 상태 재조회에 실패했습니다: {type(exc).__name__}")
        if not isinstance(result, dict) or not result.get("ok") or not isinstance(task, dict) or not task.get("paused"):
            return _partial_write_result(task_id, "pause_task", "일시정지 응답 후 Task 상태에서 paused를 확인하지 못했습니다.")
        activity_updated = bool(result.get("activity_updated")) and not already_paused
        try:
            activity_verified = already_paused or (
                activity_updated and _verify_cowork_activity(client, task_id, "pause_task", f"cowork-pause-{task_id}")
            )
        except Exception:
            activity_verified = False
        return json.dumps({"ok": True, "verified": True, "task_id": task_id, "paused": True, "already_paused": already_paused, "activity_updated": activity_updated, "activity_verified": activity_verified, "partial_write": not activity_verified, "cowork_session_paused": False}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_register_task_assets(
    task_id: int,
    target: str,
    assets_json: str,
    confirmation: str,
) -> str:
    """Register already observed in-scope IP, service, or endpoint metadata in ARTEx Test Assets.

    This does not discover assets or contact the target. The Cowork preflight
    and ARTEx server both verify task scope, exact human allow, and deny rules;
    every URL must remain on the authorized origin. Credentials, query strings,
    path traversal, and write-capable endpoint methods are rejected. The server
    stores the batch atomically. Requires `CONFIRM insert_assets task=<id>`.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id는 양의 정수여야 합니다.")
    expected = f"CONFIRM insert_assets task={task_id}"
    if confirmation != expected:
        raise ValueError(f"자산 등록에는 confirmation={expected!r}가 필요합니다.")
    assets = _validate_task_assets(assets_json, target)
    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        try:
            result = client.register_cowork_assets(task_id, target, assets, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "insert_assets", f"자산 등록 응답을 확인하지 못했습니다: {type(exc).__name__}", target_contacted=False)
        if not isinstance(result, dict):
            return _partial_write_result(task_id, "insert_assets", "ARTEx 자산 등록 응답 형식을 확인할 수 없습니다.", target_contacted=False)
        rows = result.get("results")
        errors = result.get("errors") or []
        if errors or not isinstance(rows, list) or len(rows) != len(assets):
            return _partial_write_result(task_id, "insert_assets", "자산 응답 건수가 요청과 일치하지 않습니다.", asset_results=rows, errors=errors, target_contacted=False)
        ids = {row.get("id") for row in rows if isinstance(row, dict) and isinstance(row.get("id"), int) and row.get("id") > 0}
        if len(ids) != len(assets):
            return _partial_write_result(task_id, "insert_assets", "ARTEx가 모든 자산의 ID를 반환하지 않았습니다.", asset_results=rows, target_contacted=False)
        if any(
            not isinstance(row, dict)
            or not isinstance(row.get("index"), int)
            or isinstance(row.get("index"), bool)
            or row["index"] < 0
            or row["index"] >= len(assets)
            or row.get("type") != assets[row["index"]].get("type")
            for row in rows
        ):
            return _partial_write_result(task_id, "insert_assets", "ARTEx 자산 응답의 인덱스 또는 유형이 요청과 일치하지 않습니다.", asset_ids=sorted(ids), target_contacted=False)
        try:
            surface = client.get_task_surface(task_id, "assets", page=1, size=200)
        except Exception as exc:
            return _partial_write_result(task_id, "insert_assets", f"자산 ID는 반환됐지만 Test Assets 재조회에 실패했습니다: {type(exc).__name__}", asset_ids=sorted(ids), target_contacted=False)
        expected_by_id = {row["id"]: assets[row["index"]] for row in rows}
        if not _asset_readback_matches(surface, task_id, expected_by_id):
            return _partial_write_result(task_id, "insert_assets", "자산 ID는 반환됐지만 Test Assets 재조회에서 task 소속 또는 저장 필드가 일치하지 않습니다.", asset_ids=sorted(ids), target_contacted=False)
        activity_id = f"cowork-assets-{task_id}-{rows[0]['id']}"
        try:
            activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(client, task_id, "insert_assets", activity_id)
        except Exception:
            activity_verified = False
        return json.dumps({
            "ok": activity_verified,
            "verified": activity_verified,
            "task_id": task_id,
            "target": target,
            "asset_ids": sorted(ids),
            "asset_count": len(ids),
            "surface": "assets",
            "activity_updated": bool(result.get("activity_updated")),
            "activity_verified": activity_verified,
            "partial_write": not activity_verified,
            "activity_error": result.get("activity_error") or None,
            "target_contacted": False,
        }, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_report_confirmed_finding(
    task_id: int,
    vulnclass: str,
    name: str,
    severity: str,
    summary: str,
    evidence: str,
    target: str,
    confirmation: str,
) -> str:
    """Register one already confirmed, reproducible vulnerability as an ARTEx finding.

    Do not use for observations, hypotheses, candidates, or incomplete evidence.
    This creates an official finding and updates ARTEx finding counts/workflows.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id는 양의 정수여야 합니다.")
    expected = f"CONFIRM report_finding task={task_id}"
    if confirmation != expected:
        raise ValueError(f"등록하려면 confirmation={expected!r}가 필요합니다.")
    values = {key: _clean_field(key, value) for key, value in {
        "vulnclass": vulnclass, "name": name, "summary": summary, "evidence": evidence,
    }.items()}
    if severity not in {"critical", "high", "medium", "low"}:
        raise ValueError("severity는 critical, high, medium, low 중 하나여야 합니다.")
    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        try:
            result = client.report_confirmed_finding(task_id, values["vulnclass"], values["name"], severity, values["summary"], values["evidence"], target, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "report_finding", f"Finding 등록 응답을 확인하지 못했습니다: {type(exc).__name__}", formal_finding_created="unknown")
        if not isinstance(result, dict) or not result.get("ok") or not result.get("finding_id"):
            return _partial_write_result(task_id, "report_finding", "ARTEx가 Finding 생성 ID를 반환하지 않았습니다.", formal_finding_created="unknown")
        try:
            saved = client.get_finding(int(result["finding_id"]), task_id)
        except Exception as exc:
            return _partial_write_result(task_id, "report_finding", f"Finding ID는 반환됐지만 Task Finding 재조회에 실패했습니다: {type(exc).__name__}", finding_id=result["finding_id"], formal_finding_created="unknown")
        expected_finding = {
            "vulnclass": values["vulnclass"], "name": values["name"], "severity": severity,
            "summary": values["summary"], "evidence": values["evidence"],
        }
        if (
            not isinstance(saved, dict)
            or str(saved.get("task_id")) != str(task_id)
            or str(saved.get("finding_id") or saved.get("id")) != str(result["finding_id"])
            or any(saved.get(key) != value for key, value in expected_finding.items())
        ):
            return _partial_write_result(task_id, "report_finding", "Finding ID는 반환됐지만 Task Finding의 저장 내용이 일치하지 않습니다.", finding_id=result["finding_id"], formal_finding_created="unknown")
        activity_id = f"cowork-finding-{result['finding_id']}"
        try:
            activity_verified = (
                bool(result.get("idempotent_reuse")) or bool(result.get("activity_updated"))
            ) and _verify_cowork_activity(client, task_id, "report_finding", activity_id)
        except Exception:
            activity_verified = False
        return json.dumps({"ok": True, "verified": True, "native_record_verified": True, "task_id": task_id, "finding_id": result["finding_id"], "finding_node_id": result.get("finding_node_id"), "formal_finding_created": not bool(result.get("idempotent_reuse")), "idempotent_reuse": bool(result.get("idempotent_reuse")), "activity_updated": bool(result.get("activity_updated")), "activity_verified": activity_verified, "partial_write": not activity_verified, "activity_error": result.get("activity_error") or (None if activity_verified else "Finding은 확인됐지만 Cowork 활동 이력은 확인되지 않았습니다. 재시도 전에 Task 화면을 확인하세요.")}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_update_finding_status(task_id: int, finding_id: int, status: str, confirmation: str) -> str:
    """Change one finding's triage status in the named task after the operator explicitly authorizes that exact transition.

    This updates ARTEx's native finding workflow and may send configured status-change notifications.
    It does not run a retest; use the dedicated retest workflow for evidence of remediation.
    """
    if not isinstance(task_id, int) or task_id <= 0 or not isinstance(finding_id, int) or finding_id <= 0:
        raise ValueError("task_id and finding_id must be positive integers")
    if status not in {"pending", "in_progress", "confirmed", "resolved", "fixed", "false_positive", "ignored", "duplicate", "risk_accepted"}:
        raise ValueError("status must be a supported ARTEx finding status")
    expected = f"CONFIRM update_finding_status task={task_id} finding={finding_id} status={status}"
    if confirmation != expected:
        raise ValueError(f"상태 변경에는 confirmation={expected!r}가 필요합니다.")
    client = _authenticated_client()
    try:
        surface = client.get_task_surface(task_id, "findings")
        rows = surface.get("findings", []) if isinstance(surface, dict) else []
        existing = next((row for row in rows if isinstance(row, dict) and str(row.get("finding_id")) == str(finding_id)), None)
        if not existing:
            raise ValueError("finding_id가 해당 Task의 Findings 화면에 속하는지 확인되지 않았습니다.")
        try:
            result = client.update_cowork_finding_status(task_id, finding_id, status, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "update_finding_status", f"Finding 상태 변경 응답을 확인하지 못했습니다: {type(exc).__name__}", finding_id=finding_id, requested_status=status)
        if not isinstance(result, dict) or not result.get("ok") or str(result.get("finding_id")) != str(finding_id) or result.get("status") != status:
            return _partial_write_result(task_id, "update_finding_status", "ARTEx가 Finding 상태 변경 결과를 확인하지 못했습니다.", finding_id=finding_id, requested_status=status)
        try:
            verified = client.get_task_surface(task_id, "findings")
        except Exception as exc:
            return _partial_write_result(task_id, "update_finding_status", f"상태 변경 응답은 받았지만 Findings 재조회에 실패했습니다: {type(exc).__name__}", finding_id=finding_id, requested_status=status)
        saved_rows = verified.get("findings", []) if isinstance(verified, dict) else []
        saved = next((row for row in saved_rows if isinstance(row, dict) and str(row.get("finding_id")) == str(finding_id)), None)
        if not saved or saved.get("status") != status:
            return _partial_write_result(task_id, "update_finding_status", "상태 변경 응답은 받았지만 Task Findings 재조회에서 결과를 확인하지 못했습니다.", finding_id=finding_id, requested_status=status)
        activity_verified = False
        if result.get("changed"):
            seq = result.get("activity_seq")
            if not isinstance(seq, int) or seq <= 0:
                return _partial_write_result(task_id, "update_finding_status", "상태는 변경됐지만 활동 순번을 받지 못했습니다.", finding_id=finding_id, status=status, native_record_verified=True)
            try:
                activity_verified = _find_session_activity(
                    client, task_id, "cowork",
                    lambda item: str(item.get("seq")) == str(seq)
                    and item.get("worker") == "cowork"
                    and item.get("tool") == "update_finding_status"
                    and str(item.get("intent_id")) == str(result.get("finding_node_id")),
                )
            except Exception:
                activity_verified = False
            if not activity_verified:
                return _partial_write_result(task_id, "update_finding_status", "상태는 변경됐지만 Cowork 활동 이력에서 해당 기록을 확인하지 못했습니다.", finding_id=finding_id, status=status, native_record_verified=True)
        return json.dumps({"ok": True, "verified": True, "native_record_verified": True, "task_id": task_id, "finding_id": finding_id, "from": result.get("from"), "status": status, "changed": bool(result.get("changed")), "notified": bool(result.get("notified")), "activity_updated": bool(result.get("activity_updated")), "activity_verified": activity_verified, "partial_write": False}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_update_finding_report(
    task_id: int,
    finding_node_id: int,
    report: str,
    confirmation: str,
    evidence_version: int = 0,
) -> str:
    """Save a reviewed Markdown report to an existing finding in this task. Requires exact confirmation `CONFIRM update_finding_report task=<id>`; optionally pass the evidence version read from ARTEx to prevent stale report writes."""
    if not isinstance(task_id, int) or task_id <= 0 or not isinstance(finding_node_id, int) or finding_node_id <= 0:
        raise ValueError("task_id and finding_node_id must be positive integers")
    expected = f"CONFIRM update_finding_report task={task_id}"
    if confirmation != expected:
        raise ValueError(f"저장하려면 confirmation={expected!r}가 필요합니다.")
    if not isinstance(report, str) or not report.strip():
        raise ValueError("report는 비어 있을 수 없습니다.")
    report = report.strip()
    if len(report) > 120000:
        raise ValueError("report는 120000자 이하여야 합니다.")
    if any(pattern.search(report) for pattern in SECRET_PATTERNS):
        raise ValueError("report에 자격 증명처럼 보이는 문자열이 있어 저장을 거부했습니다.")
    client = _authenticated_client()
    try:
        try:
            result = client.update_finding_report(task_id, finding_node_id, report, confirmation, evidence_version or None)
        except Exception as exc:
            return _partial_write_result(task_id, "update_finding_report", f"Finding 보고서 갱신 응답을 확인하지 못했습니다: {type(exc).__name__}", finding_node_id=finding_node_id)
        if not isinstance(result, dict) or not result.get("ok") or not result.get("updated"):
            return _partial_write_result(task_id, "update_finding_report", "ARTEx가 Finding 보고서 갱신 결과를 확인하지 못했습니다.", finding_node_id=finding_node_id)
        try:
            saved = client.get_cowork_finding_report(task_id, finding_node_id)
        except Exception as exc:
            return _partial_write_result(task_id, "update_finding_report", f"보고서 갱신 응답은 받았지만 Finding 보고서 재조회에 실패했습니다: {type(exc).__name__}", finding_node_id=finding_node_id)
        if not isinstance(saved, dict) or saved.get("report") != report:
            return _partial_write_result(task_id, "update_finding_report", "보고서 갱신 응답은 받았지만 Finding 상세 재조회에서 내용을 확인하지 못했습니다.", finding_node_id=finding_node_id)
        activity_id = f"cowork-report-{finding_node_id}"
        try:
            activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(client, task_id, "update_finding_report", activity_id)
        except Exception:
            activity_verified = False
        return json.dumps({"ok": True, "verified": True, "native_record_verified": True, "task_id": task_id, "finding_node_id": finding_node_id, "activity_updated": bool(result.get("activity_updated")), "activity_verified": activity_verified, "partial_write": not activity_verified, "activity_error": result.get("activity_error") or (None if activity_verified else "보고서는 확인됐지만 Cowork 활동 이력은 확인되지 않았습니다. 재시도 전에 Task 화면을 확인하세요.")}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_record_finding_retest_result(
    task_id: int, finding_id: int, target: str, verdict: str, summary: str, evidence: str, confirmation: str,
) -> str:
    """Record a completed, evidence-backed Cowork retest in ARTEx native Finding > Retests history.

    This does not run the retest. Call only after the approved check actually ran;
    `fixed` updates the finding status using ARTEx's native workflow.
    """
    if not isinstance(task_id, int) or task_id <= 0 or not isinstance(finding_id, int) or finding_id <= 0:
        raise ValueError("task_id and finding_id must be positive integers")
    expected = f"CONFIRM record_cowork_retest task={task_id} finding={finding_id}"
    if confirmation != expected:
        raise ValueError(f"기록하려면 confirmation={expected!r}가 필요합니다.")
    if verdict not in {"reproduced", "fixed", "inconclusive"}:
        raise ValueError("verdict는 reproduced, fixed, inconclusive 중 하나여야 합니다.")
    summary = _clean_field("summary", summary)
    evidence = _clean_field("evidence", evidence)
    if len(evidence) > 128000 or any(pattern.search(value) for pattern in SECRET_PATTERNS for value in (summary, evidence)):
        raise ValueError("evidence가 너무 길거나 credential처럼 보여 기록을 거부했습니다.")
    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        try:
            result = client.record_cowork_finding_retest(task_id, finding_id, target, verdict, summary, evidence, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "record_finding_retest_result", f"재검증 기록 응답을 확인하지 못했습니다: {type(exc).__name__}", finding_id=finding_id, verdict=verdict)
        retest = result.get("retest") if isinstance(result, dict) else None
        if not isinstance(retest, dict) or retest.get("status") != "completed" or retest.get("verdict") != verdict:
            return _partial_write_result(task_id, "record_finding_retest_result", "ARTEx가 재검증 기록 ID와 완료 상태를 반환하지 않았습니다.", finding_id=finding_id, verdict=verdict)
        try:
            surface = client.get_task_surface(task_id, "retests", finding_id=finding_id)
        except Exception as exc:
            return _partial_write_result(task_id, "record_finding_retest_result", f"재검증은 반환됐지만 Finding Retests 재조회에 실패했습니다: {type(exc).__name__}", finding_id=finding_id, retest_id=retest.get("id"), verdict=verdict)
        rows = surface.get("retests", []) if isinstance(surface, dict) else []
        saved = next((row for row in rows if isinstance(row, dict) and str(row.get("id")) == str(retest.get("id"))), None)
        if (
            not saved
            or saved.get("status") != "completed"
            or saved.get("verdict") != verdict
            or str(saved.get("finding_id")) != str(finding_id)
            or saved.get("summary") != summary
            or saved.get("evidence") != evidence
        ):
            return _partial_write_result(task_id, "record_finding_retest_result", "재검증 ID는 반환됐지만 ARTEx Retests의 저장 내용 전체가 일치하지 않습니다.", finding_id=finding_id, retest_id=retest.get("id"), verdict=verdict)
        activity_id = f"cowork-retest-{retest['id']}"
        try:
            activity_verified = (
                bool(result.get("idempotent_reuse")) or bool(result.get("activity_updated"))
            ) and _verify_cowork_activity(client, task_id, "record_finding_retest_result", activity_id)
        except Exception:
            activity_verified = False
        return json.dumps({"ok": True, "verified": True, "native_record_verified": True, "task_id": task_id, "finding_id": finding_id, "retest_id": retest["id"], "verdict": verdict, "surface": "finding_retests", "activity_updated": bool(result.get("activity_updated")), "idempotent_reuse": bool(result.get("idempotent_reuse")), "activity_verified": activity_verified, "partial_write": not activity_verified}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_bind_cowork_traffic_to_finding(
    task_id: int,
    finding_id: int,
    target: str,
    traffic_refs_json: str,
    confirmation: str,
) -> str:
    """Attach already captured, same-task Cowork traffic as native evidence to an existing Finding.

    This does not send requests. Requires the exact authorized task origin and
    `CONFIRM bind_cowork_traffic task=<id> finding=<id>`.
    """
    if not isinstance(task_id, int) or task_id <= 0 or not isinstance(finding_id, int) or finding_id <= 0:
        raise ValueError("task_id and finding_id must be positive integers")
    expected = f"CONFIRM bind_cowork_traffic task={task_id} finding={finding_id}"
    if confirmation != expected:
        raise ValueError(f"저장하려면 confirmation={expected!r}가 필요합니다.")
    if not isinstance(traffic_refs_json, str) or len(traffic_refs_json) > 48_000:
        raise ValueError("traffic_refs_json은 48000자 이하여야 합니다.")
    try:
        refs = json.loads(traffic_refs_json)
    except json.JSONDecodeError as exc:
        raise ValueError("traffic_refs_json은 JSON 배열이어야 합니다.") from exc
    if not isinstance(refs, list) or not 1 <= len(refs) <= 20:
        raise ValueError("traffic_refs_json에는 1~20개 캡처가 필요합니다.")
    normalized = []
    seen_capture_ids: set[str] = set()
    for index, item in enumerate(refs):
        if not isinstance(item, dict) or set(item) - {"traffic_id", "role", "note"}:
            raise ValueError(f"traffic_refs_json[{index}]의 필드가 올바르지 않습니다.")
        capture_id = item.get("traffic_id")
        if not isinstance(capture_id, str) or not re.fullmatch(
            rf"cowork-t{task_id}-[a-f0-9]{{32}}-[1-9][0-9]*", capture_id
        ):
            raise ValueError(f"traffic_refs_json[{index}].traffic_id가 이 Task에 속하지 않습니다.")
        if capture_id in seen_capture_ids:
            raise ValueError(f"traffic_refs_json[{index}].traffic_id가 중복되었습니다.")
        seen_capture_ids.add(capture_id)
        role = item.get("role", "supporting")
        if role not in {"baseline", "proof", "verification", "supporting"}:
            raise ValueError(f"traffic_refs_json[{index}].role 값이 올바르지 않습니다.")
        note = item.get("note", "")
        if not isinstance(note, str) or len(note) > 500 or any(pattern.search(note) for pattern in SECRET_PATTERNS):
            raise ValueError(f"traffic_refs_json[{index}].note가 너무 길거나 민감정보처럼 보여 거부했습니다.")
        normalized.append({"traffic_id": capture_id, "role": role, "note": note})

    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        finding = client.get_finding(finding_id, task_id)
        if not isinstance(finding, dict) or str(finding.get("task_id")) != str(task_id):
            raise RuntimeError("Finding이 지정한 Task에 속한다는 것을 확인하지 못했습니다.")
        try:
            result = client.bind_cowork_traffic_to_finding(
                task_id, finding_id, target, normalized, confirmation,
            )
        except Exception as exc:
            return _partial_write_result(
                task_id, "bind_cowork_traffic",
                f"트래픽 연결 응답을 확인하지 못했습니다: {type(exc).__name__}",
                finding_id=finding_id,
            )
        if not isinstance(result, dict) or not result.get("ok") or not result.get("verified"):
            return _partial_write_result(
                task_id, "bind_cowork_traffic", "ARTEx가 트래픽 연결 결과를 검증하지 못했습니다.",
                finding_id=finding_id,
            )
        try:
            saved = client.get_finding_traffic(task_id, finding_id)
            bindings = saved.get("bindings", []) if isinstance(saved, dict) else []
            saved_ids = {
                str(binding.get("snapshot", {}).get("source_traffic_id")): binding
                for binding in bindings if isinstance(binding, dict)
            }
            for item in normalized:
                saved_binding = saved_ids.get(item["traffic_id"])
                if not saved_binding:
                    raise RuntimeError("일부 캡처 ID가 Finding 증거에서 확인되지 않았습니다.")
                if saved_binding.get("role") != item["role"] or saved_binding.get("note", "") != item["note"]:
                    raise RuntimeError("Finding 증거에 저장된 캡처의 역할 또는 메모가 요청과 다릅니다.")
        except Exception as exc:
            return _partial_write_result(
                task_id, "bind_cowork_traffic",
                f"연결 응답은 받았지만 Finding 트래픽 증거 재조회에 실패했습니다: {type(exc).__name__}",
                finding_id=finding_id,
            )
        activity_verified = False
        if result.get("tool_use_id"):
            try:
                activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(
                    client, task_id, "bind_cowork_traffic", str(result["tool_use_id"]),
                )
            except Exception:
                activity_verified = False
        return json.dumps({
            "ok": True, "verified": True, "native_record_verified": True,
            "task_id": task_id, "finding_id": finding_id,
            "bound_capture_ids": [item["traffic_id"] for item in normalized],
            "activity_updated": bool(result.get("activity_updated")),
            "activity_verified": activity_verified, "partial_write": not activity_verified,
            "activity_error": result.get("activity_error") or (
                None if activity_verified else "증거 연결은 확인됐지만 Task 활동 기록은 확인되지 않았습니다. 재시도 전에 화면을 확인하세요."
            ),
        }, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_decide_intercept(task_id: int, pending_id: int, decision: str, confirmation: str) -> str:
    """Apply an operator-directed decision to one pending ARTEx intercept for this task.

    This can release a waiting tool call. Call only when the human explicitly
    instructed allow or deny for this exact pending ID; never infer approval.
    """
    if not isinstance(task_id, int) or task_id <= 0 or not isinstance(pending_id, int) or pending_id <= 0:
        raise ValueError("task_id and pending_id must be positive integers")
    if decision not in {"allowed", "denied"}:
        raise ValueError("decision must be allowed or denied")
    expected = f"CONFIRM decide_intercept task={task_id} pending={pending_id} decision={decision}"
    if confirmation != expected:
        raise ValueError(f"결정하려면 confirmation={expected!r}가 필요합니다.")
    client = _authenticated_client()
    try:
        surface = client.get_task_surface(task_id, "intercept_approvals", page=1, size=100)
        items = surface.get("items", []) if isinstance(surface, dict) else []
        pending = next((item for item in items if isinstance(item, dict) and item.get("id") == pending_id), None)
        if not pending or str(pending.get("task_id")) != str(task_id) or pending.get("status") != "pending":
            raise ValueError("승인 대기 ID가 해당 Task에 속한 pending 항목인지 확인되지 않았습니다.")
        try:
            result = client.decide_cowork_intercept(task_id, pending_id, decision, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "decide_intercept", f"승인 결정 응답을 확인하지 못했습니다: {type(exc).__name__}", pending_id=pending_id, decision=decision, approval_action_may_have_taken_effect=(decision == "allowed"))
        if not isinstance(result, dict) or not result.get("ok") or int(result.get("pending_id", 0)) != pending_id or result.get("decision") != decision:
            return _partial_write_result(task_id, "decide_intercept", "ARTEx가 승인 결정 결과를 확인하지 못했습니다.", pending_id=pending_id, decision=decision, approval_action_may_have_taken_effect=(decision == "allowed"))
        try:
            verified_surface = client.get_task_surface(task_id, "intercept_approvals", page=1, size=100)
        except Exception as exc:
            return _partial_write_result(task_id, "decide_intercept", f"결정 응답은 받았지만 승인 기록 재조회에 실패했습니다: {type(exc).__name__}", pending_id=pending_id, decision=decision, approval_action_may_have_taken_effect=(decision == "allowed"))
        verified_items = verified_surface.get("items", []) if isinstance(verified_surface, dict) else []
        saved = next((item for item in verified_items if isinstance(item, dict) and str(item.get("id")) == str(pending_id)), None)
        if not saved or str(saved.get("task_id")) != str(task_id) or saved.get("status") != decision:
            return _partial_write_result(task_id, "decide_intercept", "결정 응답은 받았지만 Task 승인 기록의 상태가 일치하지 않습니다.", pending_id=pending_id, decision=decision, approval_action_may_have_taken_effect=(decision == "allowed"))
        activity_id = f"cowork-intercept-{pending_id}"
        try:
            activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(client, task_id, "decide_intercept", activity_id)
        except Exception:
            activity_verified = False
        return json.dumps({"ok": True, "verified": True, "task_id": task_id, "pending_id": pending_id, "decision": decision, "activity_updated": bool(result.get("activity_updated")), "activity_verified": activity_verified, "partial_write": not activity_verified, "warning": "승인 결정은 대기 중인 도구 실행을 재개할 수 있습니다."}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_add_task_intents(
    task_id: Annotated[int, Field(description="Positive ARTEx task ID. Use only the explicitly selected task.")],
    intents_json: Annotated[str, Field(description="JSON array of 1-20 objects: {summary, priority (0-10), parent_ids?}. Do not include unsupported target work; this records planning metadata only.")],
    target: Annotated[str, Field(description="Required HTTP(S) ORIGIN (scheme + host + optional port, no path/query), matching this task's scope and human allow. Authorization metadata only; this tool sends no target request.")],
    confirmation: Annotated[str, Field(description="Exact operation confirmation: CONFIRM add_cowork_intents task=<task_id>.")],
) -> str:
    """Append up to 20 bounded Cowork plan items to this task's native ARTEx exploration graph.

    This records planning metadata only; it does not enqueue or run ARTEx workers.
    Each item is {summary, priority (0-10), parent_ids?}; parents must be task-local
    confirmed fact/finding node IDs. Requires explicit operator authorization.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id must be a positive integer")
    expected = f"CONFIRM add_cowork_intents task={task_id}"
    if confirmation != expected:
        raise ValueError(f"기록하려면 confirmation={expected!r}가 필요합니다.")
    try:
        intents = json.loads(intents_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("intents_json은 JSON 배열이어야 합니다.") from exc
    if not isinstance(intents, list) or not 1 <= len(intents) <= 20:
        raise ValueError("intents_json은 1~20개 객체 배열이어야 합니다.")
    clean: list[dict[str, Any]] = []
    seen_summaries: set[str] = set()
    for index, item in enumerate(intents):
        if not isinstance(item, dict):
            raise ValueError(f"intent {index} must be an object")
        summary = _clean_field("summary", item.get("summary"))
        if summary in seen_summaries:
            raise ValueError(f"intent {index} duplicates a summary in the same batch")
        seen_summaries.add(summary)
        priority = item.get("priority", 5)
        if not isinstance(priority, int) or not 0 <= priority <= 10:
            raise ValueError(f"intent {index} priority must be 0-10")
        parents = item.get("parent_ids", [])
        if not isinstance(parents, list) or any(not isinstance(parent, int) or parent <= 0 for parent in parents):
            raise ValueError(f"intent {index} parent_ids must be positive integer node IDs")
        clean.append({"summary": summary, "priority": priority, "parent_ids": parents})
    client = _authenticated_client()
    try:
        _verify_context(client, task_id, target)
        try:
            result = client.add_cowork_intents(task_id, clean, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "add_cowork_intents", f"탐색 intent 기록 응답을 확인하지 못했습니다: {type(exc).__name__}")
        ids = result.get("intent_ids") if isinstance(result, dict) else None
        if not isinstance(ids, list) or len(ids) != len(clean) or any(not isinstance(i, int) or i <= 0 for i in ids):
            return _partial_write_result(task_id, "add_cowork_intents", "ARTEx가 각 탐색 intent의 ID를 반환하지 않았습니다.")
        try:
            graph = client.get_task_surface(task_id, "exploration")
        except Exception as exc:
            return _partial_write_result(task_id, "add_cowork_intents", f"intent ID는 반환됐지만 탐색 그래프 재조회에 실패했습니다: {type(exc).__name__}", intent_ids=ids)
        visible = _collect_ids(graph)
        if not set(ids) <= visible:
            return _partial_write_result(task_id, "add_cowork_intents", "반환된 intent ID 일부가 탐색 그래프에 없습니다.", intent_ids=ids)
        nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
        edges = graph.get("edges", []) if isinstance(graph, dict) else []
        by_id = {str(node.get("id")): node for node in nodes if isinstance(node, dict)}
        for item, intent_id in zip(clean, ids):
            saved = by_id.get(str(intent_id))
            payload = _graph_payload(saved) if saved else {}
            expected_priority = item["priority"] or 5
            if (
                not saved
                or saved.get("type") != "intent"
                or payload.get("summary") != item["summary"]
                or saved.get("priority") != expected_priority
            ):
                return _partial_write_result(task_id, "add_cowork_intents", "intent ID는 보였지만 저장된 내용 또는 우선순위가 일치하지 않습니다.", intent_ids=ids)
            for parent_id in item["parent_ids"]:
                if not any(
                    isinstance(edge, dict)
                    and str(edge.get("src")) == str(parent_id)
                    and str(edge.get("dst")) == str(intent_id)
                    and edge.get("rel") == "derived_from"
                    for edge in edges
                ):
                    return _partial_write_result(task_id, "add_cowork_intents", "intent는 저장됐지만 증거 의존 관계를 탐색 그래프에서 확인하지 못했습니다.", intent_ids=ids)
        activity_id = f"cowork-intents-{task_id}-{ids[0]}"
        try:
            activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(client, task_id, "add_intent", activity_id)
        except Exception:
            activity_verified = False
        return json.dumps({"ok": True, "verified": True, "task_id": task_id, "intent_ids": ids, "intent_count": len(ids), "surface": "exploration_graph", "activity_updated": bool(result.get("activity_updated")), "activity_verified": activity_verified, "partial_write": not activity_verified, "worker_enqueued": False}, ensure_ascii=False)
    finally:
        client.clear_token()


@server.tool()
def artex_complete_cowork_intent(
    task_id: Annotated[int, Field(description="Positive ARTEx task ID that owns the intent.")],
    intent_id: Annotated[int, Field(description="Positive task-local intent node ID returned by artex_add_task_intents or the Task intents surface.")],
    state: Annotated[str, Field(description="Required enum: 'done' or 'blocked'. 'done' requires evidence; use 'blocked' when work was not completed.")],
    summary: Annotated[str, Field(description="Concise outcome summary. Identify synthetic acceptance work as synthetic; do not imply native ARTEx worker execution.")],
    evidence: Annotated[str, Field(description="Required for state='done'. Describe only work already completed; no credentials, tokens, cookies, or personal data.")],
    confirmation: Annotated[str, Field(description="Exact operation confirmation: CONFIRM complete_cowork_intent task=<task_id> intent=<intent_id> state=<state>.")],
) -> str:
    """Record a Cowork-completed or blocked intent in ARTEx native Worker session history.

    This closes an intent based on work already performed in Cowork. It does not
    enqueue a worker, prove a goal, or perform any target request. `done` requires
    evidence; `blocked` records why work could not be completed.
    """
    if not isinstance(task_id, int) or task_id <= 0 or not isinstance(intent_id, int) or intent_id <= 0:
        raise ValueError("task_id and intent_id must be positive integers")
    if state not in {"done", "blocked"}:
        raise ValueError("state must be done or blocked")
    expected = f"CONFIRM complete_cowork_intent task={task_id} intent={intent_id} state={state}"
    if confirmation != expected:
        raise ValueError(f"기록하려면 confirmation={expected!r}가 필요합니다.")
    clean_summary = _clean_field("summary", summary)
    clean_evidence = evidence.strip() if isinstance(evidence, str) else ""
    if state == "done":
        clean_evidence = _clean_field("evidence", clean_evidence)
    if len(clean_evidence) > 128_000:
        raise ValueError("evidence must be at most 128000 characters")
    if any(pattern.search(clean_evidence) for pattern in SECRET_PATTERNS):
        raise ValueError("evidence에 자격 증명처럼 보이는 문자열이 있어 저장을 거부했습니다.")
    client = _authenticated_client()
    try:
        try:
            result = client.complete_cowork_intent(task_id, intent_id, state, clean_summary, clean_evidence, confirmation)
        except Exception as exc:
            return _partial_write_result(task_id, "complete_cowork_intent", f"intent 완료 기록 응답을 확인하지 못했습니다: {type(exc).__name__}", intent_id=intent_id, requested_state=state)
        if not isinstance(result, dict) or not result.get("ok") or str(result.get("intent_id")) != str(intent_id) or result.get("state") != state:
            return _partial_write_result(task_id, "complete_cowork_intent", "ARTEx가 intent 완료 결과를 확인하지 못했습니다.", intent_id=intent_id, requested_state=state)
        try:
            intent_index = client.get_task_surface(task_id, "intents", size=1, before=intent_id + 1)
        except Exception as exc:
            return _partial_write_result(task_id, "complete_cowork_intent", f"완료 응답은 받았지만 intent 목록 재조회에 실패했습니다: {type(exc).__name__}", intent_id=intent_id, requested_state=state)
        intent_items = intent_index.get("items", []) if isinstance(intent_index, dict) else []
        saved_intent = next((item for item in intent_items if isinstance(item, dict) and str(item.get("id")) == str(intent_id)), None)
        if not saved_intent or saved_intent.get("state") != state:
            return _partial_write_result(task_id, "complete_cowork_intent", "완료 응답은 받았지만 Task Worker intent 목록에서 상태를 확인하지 못했습니다.", intent_id=intent_id, requested_state=state)
        try:
            intent_history_verified = _find_session_activity(
                client, task_id, f"intent:{intent_id}",
                lambda item: str(item.get("intent_id")) == str(intent_id)
                and item.get("tool") == "complete_intent"
                and item.get("summary") == clean_summary,
                expected_detail=clean_evidence,
            )
        except Exception as exc:
            return _partial_write_result(task_id, "complete_cowork_intent", f"intent 상태는 변경됐지만 intent 세션 이력 재조회에 실패했습니다: {type(exc).__name__}", intent_id=intent_id, state=state, native_record_verified=True)
        if not intent_history_verified:
            return _partial_write_result(task_id, "complete_cowork_intent", "intent 상태는 변경됐지만 intent 세션 기록에서 내용을 확인하지 못했습니다.", intent_id=intent_id, state=state, native_record_verified=True)
        try:
            activity_verified = _verify_cowork_activity(client, task_id, "complete_intent", f"cowork-intent-{intent_id}")
        except Exception:
            activity_verified = False
        return json.dumps({"ok": True, "verified": True, "native_record_verified": True, "task_id": task_id, "intent_id": intent_id, "state": state, "session_key": f"intent:{intent_id}", "surface": "sessions", "activity_updated": bool(result.get("activity_updated")), "activity_verified": activity_verified, "partial_write": not activity_verified}, ensure_ascii=False)
    finally:
        client.clear_token()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
