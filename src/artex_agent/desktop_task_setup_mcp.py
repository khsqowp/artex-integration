"""ARTEx task setup and task intercept-rule tools for explicit Cowork requests.

Setup supports append operations, task-scoped goal/constraint updates and
deletes, and task-scope deletion. Intercept rules support operation-specific
create/update/delete/toggle calls. No task execution or target-request tools
are exposed here. The client enforces local port 8787.
"""

from __future__ import annotations

import json

import keyring
from mcp.server.fastmcp import FastMCP

from .artex_api import ArtexClient, task_intercept_rule_confirmation, task_setup_confirmation
from .auth_store import SERVICE, USERNAME


server = FastMCP("artex-task-setup")


def _authenticated_client() -> ArtexClient:
    password = keyring.get_password(SERVICE, USERNAME)
    if not password:
        raise RuntimeError("ARTEx 자격 증명이 없습니다. 먼저 artex-auth-store를 실행하세요.")
    client = ArtexClient()
    client.login(password)
    return client


def _confirmation_ok(confirmation: str, operation: str, task_id: int) -> bool:
    return isinstance(confirmation, str) and confirmation == f"CONFIRM {operation} task={int(task_id)}"


def _rows(payload, key: str) -> list[dict]:
    rows = payload.get(key) if isinstance(payload, dict) else None
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise RuntimeError(f"ARTEx {key} 재조회 응답 형식이 올바르지 않습니다.")
    return rows


def _check_task_id(task_id: int) -> None:
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id는 양의 정수여야 합니다.")


def _verify_cowork_activity(client: ArtexClient, task_id: int, tool: str, tool_use_id: str) -> bool:
    """Search newest-first pages with a hard cap for the task's Cowork activity."""
    before = 0
    for _ in range(5):
        surface = client.get_task_surface(
            task_id, "session_history", session="cowork", page=1, size=500, before=before,
        )
        if not isinstance(surface, dict):
            return False
        items = surface.get("items", [])
        if any(
            isinstance(item, dict)
            and item.get("worker") == "cowork"
            and item.get("tool") == tool
            and item.get("tool_use_id") == tool_use_id
            for item in items
        ):
            return True
        if not surface.get("has_more"):
            return False
        try:
            cursor = int(surface.get("earliest_cursor") or 0)
        except (TypeError, ValueError):
            return False
        if cursor <= 0 or cursor == before:
            return False
        before = cursor
    return False


@server.tool()
def artex_manage_task_intercept_rule(
    task_id: int,
    operation: str,
    confirmation: str,
    rule_id: int = 0,
    enabled: bool = True,
    action: str = "block",
    kind: str = "",
    pattern: str = "",
    note: str = "",
) -> str:
    """Create, replace, remove, or toggle one task-owned intercept rule.

    This changes which traffic the ARTEx engine permits or blocks. Requires an
    exact operation-specific confirmation; never use to widen scope implicitly.
    """
    _check_task_id(task_id)
    if operation not in {"create", "update", "delete", "toggle"}:
        raise ValueError("operation은 create, update, delete, toggle 중 하나여야 합니다.")
    if operation != "create":
        if not isinstance(rule_id, int) or rule_id <= 0:
            raise ValueError("update, delete, toggle에는 양의 rule_id가 필요합니다.")
    expected = task_intercept_rule_confirmation(
        task_id, operation, rule_id=rule_id, enabled=enabled,
        action=action, kind=kind, pattern=pattern, note=note,
    )
    if confirmation != expected:
        raise ValueError(f"확인 문자열이 일치하지 않습니다. 필요한 값: {expected}")

    client = _authenticated_client()
    try:
        before = _rows(client.get_task_surface(task_id, "intercept_rules"), "rules")
        if operation != "create":
            if not any(int(row.get("id") or 0) == rule_id for row in before):
                raise ValueError("rule_id가 지정한 Task의 현재 규칙 목록에 없습니다. 쓰기를 수행하지 않았습니다.")
        write_error = None
        try:
            result = client.manage_task_intercept_rule(
                task_id, operation, confirmation, rule_id=rule_id, enabled=enabled,
                action=action, kind=kind, pattern=pattern, note=note,
            )
        except Exception as exc:
            result = None
            write_error = type(exc).__name__

        try:
            listing = client.get_task_surface(task_id, "intercept_rules")
            rules = _rows(listing, "rules")
        except Exception as exc:
            return _uncertain_write(task_id, f"{operation}_intercept_rule", f"규칙 쓰기 후 재조회 실패: {type(exc).__name__}", result if isinstance(result, dict) else None)

        saved_id = int(result.get("id") or result.get("rule_id") or 0) if isinstance(result, dict) else 0
        if operation == "create" and saved_id <= 0 and write_error:
            before_ids = {int(row.get("id") or 0) for row in before}
            new_matches = [row for row in rules if int(row.get("id") or 0) not in before_ids and all((
                row.get("action") == action,
                row.get("kind") == kind,
                row.get("pattern") == pattern.strip(),
                row.get("note", "") == note.strip()[:500],
                bool(row.get("enabled")) == bool(enabled),
            ))]
            if len(new_matches) == 1:
                saved_id = int(new_matches[0].get("id") or 0)
        expected_rule = next((row for row in rules if int(row.get("id") or 0) == (saved_id if operation == "create" else rule_id)), None)
        if operation == "delete":
            verified = (
                any(int(row.get("id") or 0) == rule_id for row in before)
                and not any(int(row.get("id") or 0) == rule_id for row in rules)
                and (write_error is not None or (isinstance(result, dict) and result.get("deleted") is True))
            )
        elif operation == "create":
            verified = saved_id > 0 and isinstance(expected_rule, dict) and all((
                expected_rule.get("action") == action,
                expected_rule.get("kind") == kind,
                expected_rule.get("pattern") == pattern.strip(),
                expected_rule.get("note", "") == note.strip()[:500],
                bool(expected_rule.get("enabled")) == bool(enabled),
            ))
        elif operation == "update":
            verified = isinstance(expected_rule, dict) and all((
                expected_rule.get("action") == action,
                expected_rule.get("kind") == kind,
                expected_rule.get("pattern") == pattern.strip(),
                expected_rule.get("note", "") == note.strip()[:500],
                bool(expected_rule.get("enabled")) == bool(enabled),
            ))
        else:
            verified = any(
                int(row.get("id") or 0) == rule_id and bool(row.get("enabled")) == bool(enabled)
                for row in rules
            )
        if not verified:
            return _uncertain_write(task_id, f"{operation}_intercept_rule", "규칙 변경 후 ARTEx 목록 재조회가 일치하지 않습니다.", result if isinstance(result, dict) else None)
        saved = expected_rule if isinstance(expected_rule, dict) else {"deleted": rule_id}
        activity_id = result.get("activity_tool_use_id", "") if isinstance(result, dict) else ""
        return _write_result(
            task_id, "rule", saved, result if isinstance(result, dict) else {},
            "manage_task_intercept_rule", activity_id, client,
            operation=operation, write_response_uncertain=bool(write_error),
        )
    finally:
        client.clear_token()


def _write_result(task_id: int, key: str, saved: dict, result: dict, tool: str, tool_use_id: str, client: ArtexClient, **extra) -> str:
    """Return native-write and activity-feed verification separately to prevent blind retries."""
    activity_updated = bool(result.get("activity_updated"))
    try:
        activity_verified = activity_updated and _verify_cowork_activity(client, task_id, tool, tool_use_id)
        activity_error = result.get("activity_error") or (None if activity_verified else "Task 변경은 저장됐지만 Cowork 활동 이력을 확인하지 못했습니다. 재시도 전에 Task 화면을 확인하세요.")
    except Exception as exc:
        activity_verified = False
        activity_error = f"Task 변경은 저장됐지만 Cowork 활동 이력을 재조회하지 못했습니다: {type(exc).__name__}. 재시도 전에 Task 화면을 확인하세요."
    payload = {
        "ok": True,
        "verified": True,
        "native_record_verified": True,
        "activity_updated": activity_updated,
        "activity_verified": activity_verified,
        "partial_write": not activity_verified,
        "activity_error": activity_error,
        "task_id": task_id,
        key: saved,
        **extra,
    }
    return json.dumps(payload, ensure_ascii=False, default=str)


def _uncertain_write(task_id: int, operation: str, reason: str, record: dict | None = None) -> str:
    """Represent an ambiguous post-write result so Cowork inspects before retrying."""
    return json.dumps({
        "ok": False,
        "verified": False,
        "partial_write": True,
        "native_record_verified": False,
        "activity_updated": False,
        "activity_verified": False,
        "task_id": task_id,
        "operation": operation,
        "record": record,
        "error": reason,
        "retry_guidance": "쓰기 결과가 불확실합니다. 재시도 전에 Task 화면을 확인하세요.",
    }, ensure_ascii=False, default=str)


@server.tool()
def artex_add_goal(task_id: int, text: str, confirmation: str, vulnclass: str = "") -> str:
    """Append one goal without starting ARTEx's native planner. Requires `CONFIRM add_goal task=<id>`."""
    _check_task_id(task_id)
    if not _confirmation_ok(confirmation, "add_goal", task_id):
        raise ValueError(f"확인 문자열이 일치하지 않습니다. 필요한 값: CONFIRM add_goal task={int(task_id)}")
    text = text.strip() if isinstance(text, str) else ""
    vulnclass = vulnclass.strip() if isinstance(vulnclass, str) else ""
    if not text:
        raise ValueError("goal text는 비어 있을 수 없습니다.")
    client = _authenticated_client()
    try:
        try:
            result = client.add_goal(task_id, text, confirmation, vulnclass)
        except Exception as exc:
            return _uncertain_write(task_id, "add_goal", f"ARTEx 쓰기 응답을 확인하지 못했습니다: {type(exc).__name__}")
        saved_goal = result.get("goal") if isinstance(result, dict) else None
        if not isinstance(saved_goal, dict) or not saved_goal.get("id"):
            return _uncertain_write(task_id, "add_goal", "ARTEx 응답에서 목표 생성 ID를 확인하지 못했습니다.")
        try:
            goals = _rows(client.list_goals(task_id), "goals")
        except Exception as exc:
            return _uncertain_write(task_id, "add_goal", f"목표는 반환됐지만 Task 목표 목록을 재조회하지 못했습니다: {type(exc).__name__}", saved_goal)
        saved = next((row for row in goals if str(row.get("id")) == str(saved_goal["id"])), None)
        if not saved or saved.get("text") != text or (vulnclass and saved.get("vulnclass") != vulnclass):
            return _uncertain_write(task_id, "add_goal", "목표는 반환됐지만 Task 목표 목록의 내용이 일치하지 않습니다.", saved_goal)
        activity_id = f"cowork-goal-{saved_goal['id']}"
        return _write_result(task_id, "goal", saved, result, "add_goal", activity_id, client, task_may_resume=False)
    finally:
        client.clear_token()


@server.tool()
def artex_add_constraint(task_id: int, kind: str, text: str, confirmation: str) -> str:
    """Append one allow/deny behavior constraint; requires exact operator confirmation `CONFIRM add_constraint task=<id>`."""
    _check_task_id(task_id)
    if not _confirmation_ok(confirmation, "add_constraint", task_id):
        raise ValueError(f"확인 문자열이 일치하지 않습니다. 필요한 값: CONFIRM add_constraint task={int(task_id)}")
    text = text.strip() if isinstance(text, str) else ""
    kind = kind.strip().lower() if isinstance(kind, str) else ""
    if not text or kind not in {"allow", "deny"}:
        raise ValueError("constraint에는 비어 있지 않은 text와 allow/deny kind가 필요합니다.")
    client = _authenticated_client()
    try:
        try:
            result = client.add_constraint(task_id, text, kind, confirmation)
        except Exception as exc:
            return _uncertain_write(task_id, "add_constraint", f"ARTEx 쓰기 응답을 확인하지 못했습니다: {type(exc).__name__}")
        saved_constraint = result.get("constraint") if isinstance(result, dict) else None
        if not isinstance(saved_constraint, dict) or not saved_constraint.get("id"):
            return _uncertain_write(task_id, "add_constraint", "ARTEx 응답에서 제약 생성 ID를 확인하지 못했습니다.")
        try:
            constraints = _rows(client.list_constraints(task_id), "constraints")
        except Exception as exc:
            return _uncertain_write(task_id, "add_constraint", f"제약은 반환됐지만 Task 제약 목록을 재조회하지 못했습니다: {type(exc).__name__}", saved_constraint)
        saved = next((row for row in constraints if str(row.get("id")) == str(saved_constraint["id"])), None)
        if not saved or saved.get("kind") != kind or saved.get("text") != text:
            return _uncertain_write(task_id, "add_constraint", "제약은 반환됐지만 Task 제약 목록의 내용이 일치하지 않습니다.", saved_constraint)
        activity_id = f"cowork-constraint-{saved_constraint['id']}"
        return _write_result(task_id, "constraint", saved, result, "add_constraint", activity_id, client)
    finally:
        client.clear_token()


@server.tool()
def artex_add_task_scope(task_id: int, kind: str, value: str, confirmation: str, reason: str = "") -> str:
    """Append one scope row; this can widen a task's target. Requires exact operator confirmation `CONFIRM add_scope task=<id>`."""
    _check_task_id(task_id)
    if not _confirmation_ok(confirmation, "add_scope", task_id):
        raise ValueError(f"확인 문자열이 일치하지 않습니다. 필요한 값: CONFIRM add_scope task={int(task_id)}")
    value = value.strip() if isinstance(value, str) else ""
    reason = reason.strip() if isinstance(reason, str) else ""
    if not value:
        raise ValueError("scope value는 비어 있을 수 없습니다.")
    client = _authenticated_client()
    try:
        try:
            result = client.add_task_scope(task_id, kind, value, confirmation, reason)
        except Exception as exc:
            return _uncertain_write(task_id, "add_task_scope", f"ARTEx 쓰기 응답을 확인하지 못했습니다: {type(exc).__name__}")
        saved_scope = result.get("scope") if isinstance(result, dict) else None
        if not isinstance(saved_scope, dict) or not saved_scope.get("id"):
            return _uncertain_write(task_id, "add_task_scope", "ARTEx 응답에서 범위 생성 ID를 확인하지 못했습니다.")
        try:
            scopes = _rows(client.list_task_scope(task_id), "scope")
        except Exception as exc:
            return _uncertain_write(task_id, "add_task_scope", f"범위는 반환됐지만 Task 범위 목록을 재조회하지 못했습니다: {type(exc).__name__}", saved_scope)
        saved = next((row for row in scopes if str(row.get("id")) == str(saved_scope["id"])), None)
        if not saved or saved.get("kind") != saved_scope.get("kind") or (saved_scope.get("value") and saved.get("value") != saved_scope.get("value")):
            return _uncertain_write(task_id, "add_task_scope", "범위는 반환됐지만 Task 범위 목록의 내용이 일치하지 않습니다.", saved_scope)
        activity_id = f"cowork-scope-{task_id}-{saved_scope['id']}"
        return _write_result(task_id, "scope", saved, result, "add_task_scope", activity_id, client, scope_may_widen=True, task_may_resume=False)
    finally:
        client.clear_token()


@server.tool()
def artex_manage_task_setup(
    task_id: int, object_type: str, operation: str, object_id: int,
    confirmation: str, kind: str = "", text: str = "", vulnclass: str = "",
) -> str:
    """Update/delete one task goal or constraint, or delete one task scope row.

    Every operation requires its exact task-and-row confirmation. The MCP
    computes the update payload digest internally before calling ARTEx.
    Goal deletion and scope deletion are destructive; scope deletion changes the target set.
    These Cowork routes do not resume or enqueue ARTEx workers.
    """
    _check_task_id(task_id)
    if object_type not in {"goal", "constraint", "scope"}:
        raise ValueError("object_type must be goal, constraint, or scope")
    if operation not in {"update", "delete"} or (object_type == "scope" and operation != "delete"):
        raise ValueError("operation must be update/delete; scope supports delete only")
    if not isinstance(object_id, int) or object_id <= 0:
        raise ValueError("object_id must be a positive integer")
    noun = {"goal": "goal", "constraint": "constraint", "scope": "scope"}[object_type]
    id_label = {"goal": "goal", "constraint": "constraint", "scope": "scope"}[object_type]
    confirmation_operation = f"{operation}_{noun}"
    expected = f"CONFIRM {confirmation_operation} task={task_id} {id_label}={object_id}"
    if confirmation != expected:
        raise ValueError(f"confirmation must equal {expected}")
    server_confirmation = task_setup_confirmation(
        task_id, confirmation_operation, object_id=object_id,
        kind=kind, text=text, vulnclass=vulnclass,
    )
    client = _authenticated_client()
    try:
        if object_type == "goal":
            result = client.manage_task_goal(task_id, object_id, operation, server_confirmation, text=text, vulnclass=vulnclass)
            rows = _rows(client.list_goals(task_id), "goals")
            saved = next((row for row in rows if str(row.get("id")) == str(object_id)), None)
            if operation == "delete":
                verified = saved is None
            else:
                verified = bool(saved and saved.get("text") == text.strip() and (saved.get("vulnclass", "") or "") == vulnclass.strip())
            tool = f"{operation}_goal"
            activity_id = f"cowork-goal-{operation}-{object_id}"
        elif object_type == "constraint":
            result = client.manage_task_constraint(task_id, object_id, operation, server_confirmation, kind=kind, text=text)
            rows = _rows(client.list_constraints(task_id), "constraints")
            saved = next((row for row in rows if str(row.get("id")) == str(object_id)), None)
            if operation == "delete":
                verified = saved is None
            else:
                verified = bool(saved and saved.get("kind") == kind.strip().lower() and saved.get("text") == text.strip())
            tool = f"{operation}_constraint"
            activity_id = f"cowork-constraint-{operation}-{object_id}"
        else:
            result = client.delete_task_scope(task_id, object_id, server_confirmation)
            rows = _rows(client.list_task_scope(task_id), "scope")
            saved = next((row for row in rows if str(row.get("id")) == str(object_id)), None)
            verified = saved is None
            tool = "delete_task_scope"
            activity_id = f"cowork-scope-delete-{task_id}-{object_id}"
        if not verified:
            return _uncertain_write(task_id, f"{operation}_{object_type}", "ARTEx write completed but task-scoped readback did not match", result if isinstance(result, dict) else None)
        activity_verified = bool(result.get("activity_updated")) and _verify_cowork_activity(client, task_id, tool, activity_id)
        return json.dumps({
            "ok": True, "verified": True, "task_id": task_id, "object_type": object_type,
            "operation": operation, "object_id": object_id,
            "activity_updated": bool(result.get("activity_updated")), "activity_verified": activity_verified,
            "partial_write": not activity_verified, "task_may_resume": False,
            "scope_may_narrow": object_type == "scope",
        }, ensure_ascii=False)
    except Exception as exc:
        return _uncertain_write(task_id, f"{operation}_{object_type}", f"ARTEx response/readback uncertain: {type(exc).__name__}")
    finally:
        client.clear_token()


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
