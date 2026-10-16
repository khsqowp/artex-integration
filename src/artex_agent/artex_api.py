"""Small authenticated client for the verified local ARTEx REST surface.

The bearer token is held only in memory. This module deliberately exposes a
small endpoint allowlist, including append-only task facts and confirmed findings.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 16_000_000
TASK_DETAIL_SURFACES = (
    "overview", "sessions", "intents", "exploration", "records", "activity",
    "session_history", "broadcast", "findings", "assets", "coverage",
    "coverage_graph", "intercept_approvals", "intercept_rules", "report",
)


def task_intercept_rule_confirmation(
    task_id: int, operation: str, *, rule_id: int = 0, enabled: bool = True,
    action: str = "block", kind: str = "", pattern: str = "", note: str = "",
) -> str:
    """Bind a rule mutation confirmation to the exact operation and payload."""
    task_id = int(task_id)
    if task_id <= 0 or operation not in {"create", "update", "delete", "toggle"}:
        raise ValueError("invalid task intercept rule operation")
    if operation != "create" and int(rule_id) <= 0:
        raise ValueError("rule_id must be positive for update, delete, or toggle")
    expected = f"CONFIRM {operation}_intercept_rule task={task_id}"
    if operation != "create":
        expected += f" rule={int(rule_id)}"
    if operation == "toggle":
        return f"{expected} enabled={str(bool(enabled)).lower()}"
    if operation in {"create", "update"}:
        values = (
            str(bool(enabled)).lower(), action, kind,
            pattern.strip(), note.strip()[:500],
        )
        canonical = "".join(f"{len(value.encode('utf-8'))}:{value}" for value in values)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"{expected} payload_sha256={digest}"
    return expected


def task_setup_confirmation(
    task_id: int, operation: str, *, object_id: int = 0,
    kind: str = "", text: str = "", vulnclass: str = "",
) -> str:
    """Bind task setup changes to the exact row and normalized update payload."""
    task_id = int(task_id)
    if task_id <= 0 or operation not in {"update_goal", "delete_goal", "update_constraint", "delete_constraint", "delete_scope"}:
        raise ValueError("invalid task setup operation")
    expected = f"CONFIRM {operation} task={task_id}"
    if operation.endswith("_goal"):
        if int(object_id) <= 0:
            raise ValueError("goal ID must be positive")
        expected += f" goal={int(object_id)}"
    elif operation.endswith("_constraint"):
        if int(object_id) <= 0:
            raise ValueError("constraint ID must be positive")
        expected += f" constraint={int(object_id)}"
    elif operation == "delete_scope":
        if int(object_id) <= 0:
            raise ValueError("scope ID must be positive")
        expected += f" scope={int(object_id)}"
    if operation.startswith("update_"):
        values = [text.strip(), vulnclass.strip()] if operation == "update_goal" else [kind.strip().lower(), text.strip()]
        canonical = "".join(f"{len(value.encode('utf-8'))}:{value}" for value in values)
        expected += f" payload_sha256={hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
    return expected


class ArtexAPIError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass
class ArtexClient:
    base_url: str = os.environ.get("ARTEX_API_BASE_URL", "http://127.0.0.1:8787")
    timeout: float = 8.0
    _token: str | None = None

    def __post_init__(self) -> None:
        parts = urlsplit(self.base_url)
        if parts.scheme != "http" or parts.hostname not in {"127.0.0.1", "localhost"} or parts.port != 8787:
            raise ValueError("ARTEx 연결은 로컬 8787 포트만 허용합니다.")
        if parts.username or parts.password or parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise ValueError("ARTEx API 주소에는 인증 정보나 추가 경로를 지정할 수 없습니다.")
        self.base_url = f"http://{parts.netloc}"

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        request = Request(self.base_url.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            opener = build_opener(_NoRedirect())
            with opener.open(request, timeout=self.timeout) as response:
                raw_body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw_body) > MAX_RESPONSE_BYTES:
                    raise ArtexAPIError(
                        f"ARTEx API {method} {path}: response exceeded {MAX_RESPONSE_BYTES} bytes; "
                        "use a paged task surface instead of accepting truncated data"
                    )
                body = raw_body.decode("utf-8", errors="replace")
                if not body:
                    return None
                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    return body
        except HTTPError as exc:
            detail = exc.read(4000).decode("utf-8", errors="replace")
            raise ArtexAPIError(f"ARTEx API {method} {path}: HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError) as exc:
            raise ArtexAPIError(f"ARTEx API unavailable at {self.base_url}: {exc}") from exc

    def health(self) -> Any:
        return self._request("GET", "/api/health")

    def auth_status(self) -> Any:
        return self._request("GET", "/api/auth/status")

    def login(self, password: str) -> None:
        result = self._request("POST", "/api/auth/login", {"username": "ARTEX", "password": password})
        token = result.get("token") if isinstance(result, dict) else None
        if not token:
            raise ArtexAPIError("ARTEx login response did not contain a token")
        self._token = token

    def list_tasks(self) -> Any:
        return self._request("GET", "/api/tasks")

    def get_dashboard_snapshot(self, task_id: int = 0) -> dict[str, Any]:
        """Read the dashboard's non-secret operational panels in one bounded call."""
        task_id = int(task_id)
        if task_id < 0:
            raise ValueError("task_id must be zero (active task) or a positive task id")
        task_query = f"?task={task_id}" if task_id > 0 else ""
        activity_query = f"?task={task_id}&limit=30" if task_id > 0 else "?limit=30"
        asset_query = f"?task_id={task_id}" if task_id > 0 else ""
        paths = {
            "tasks": "/api/tasks",
            "findings": f"/api/exploration/findings{task_query}",
            "stats": f"/api/stats{task_query}",
            "pending_intercepts": "/api/intercept/pending",
            "activity": f"/api/exploration/activity{activity_query}",
            "token_stats": f"/api/exploration/tokens{task_query}",
            "conversation_tokens": "/api/tokens/conversations",
            "usage_stats": "/api/tokens/usage?days=365",
            "asset_counts": f"/api/assets/counts{asset_query}",
        }
        results: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {name: executor.submit(self._request, "GET", path) for name, path in paths.items()}
            for name, future in futures.items():
                try:
                    results[name] = future.result()
                except Exception as exc:
                    results[name] = {"read_error": str(exc), "available": False}
        return {
            "task_id": task_id or None,
            "task_selection": "explicit" if task_id > 0 else "ARTEx active task",
            "read_only": True,
            "panels": results,
            "excluded": ["traffic bodies", "LLM/API credential configuration", "system settings", "tool/plugin administration"],
        }

    def get_task(self, task_id: int) -> Any:
        return self._request("GET", f"/api/tasks/{int(task_id)}")

    def record_cowork_traffic(self, task_id: int, payload: dict[str, Any]) -> Any:
        """Persist an explicitly authorized Cowork exchange in ARTEx Traffic."""
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/traffic", payload)

    def bind_cowork_traffic_to_finding(
        self, task_id: int, finding_id: int, target: str,
        traffic_refs: list[dict[str, str]], confirmation: str,
    ) -> Any:
        """Bind task-owned Cowork captures as native evidence for a same-task Finding."""
        task_id, finding_id = int(task_id), int(finding_id)
        if task_id <= 0 or finding_id <= 0:
            raise ValueError("task_id and finding_id must be positive")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be the exact authorized task origin")
        if not isinstance(traffic_refs, list) or not 1 <= len(traffic_refs) <= 20:
            raise ValueError("traffic_refs must contain between 1 and 20 entries")
        expected = f"CONFIRM bind_cowork_traffic task={task_id} finding={finding_id}"
        if confirmation != expected:
            raise ValueError(f"confirmation must exactly equal {expected!r}")
        seen_capture_ids: set[str] = set()
        for index, ref in enumerate(traffic_refs):
            if not isinstance(ref, dict) or set(ref) - {"traffic_id", "role", "note"}:
                raise ValueError(f"traffic_refs[{index}] has an invalid shape")
            capture_id = ref.get("traffic_id")
            if not isinstance(capture_id, str) or not re.fullmatch(
                rf"cowork-t{task_id}-[a-f0-9]{{32}}-[1-9][0-9]*", capture_id
            ):
                raise ValueError(f"traffic_refs[{index}].traffic_id must belong to this task")
            if capture_id in seen_capture_ids:
                raise ValueError(f"traffic_refs[{index}].traffic_id duplicates a capture")
            seen_capture_ids.add(capture_id)
            if ref.get("role", "supporting") not in {"baseline", "proof", "verification", "supporting"}:
                raise ValueError(f"traffic_refs[{index}].role is invalid")
            if "note" in ref and (not isinstance(ref["note"], str) or len(ref["note"]) > 500):
                raise ValueError(f"traffic_refs[{index}].note must be a string of at most 500 characters")
        return self._request(
            "POST", f"/api/tasks/{task_id}/cowork/findings/{finding_id}/traffic",
            {"target": target.strip(), "traffic_refs": traffic_refs, "confirmation": confirmation},
        )

    def list_task_findings(self, task_id: int) -> Any:
        return self._request("GET", f"/api/exploration/findings?task={int(task_id)}")

    def get_finding(self, finding_id: int, context_task_id: int | None = None) -> Any:
        path = f"/api/exploration/findings/{int(finding_id)}"
        if context_task_id is not None:
            path += f"?context_task={int(context_task_id)}"
        return self._request("GET", path)

    def get_finding_traffic(self, task_id: int, finding_id: int, binding_id: int = 0) -> Any:
        task_id, finding_id = int(task_id), int(finding_id)
        if task_id <= 0 or finding_id <= 0:
            raise ValueError("task_id and finding_id must be positive")
        if binding_id < 0:
            raise ValueError("binding_id must be non-negative")
        path = f"/api/exploration/findings/{finding_id}/traffic"
        if binding_id:
            path += f"/{binding_id}"
        path += f"?context_task={task_id}"
        return self._request(
            "GET", path
        )

    def read_finding_traffic_body(
        self, task_id: int, finding_id: int, binding_id: int, side: str = "response",
        *, offset: int = 0, length: int = 8192,
    ) -> Any:
        task_id, finding_id, binding_id = int(task_id), int(finding_id), int(binding_id)
        offset, length = int(offset), int(length)
        if task_id <= 0 or finding_id <= 0 or binding_id <= 0:
            raise ValueError("task_id, finding_id, and binding_id must be positive")
        if side not in {"request", "response"} or offset < 0 or not 1 <= length <= 8192:
            raise ValueError("side must be request/response, offset non-negative, and length 1..8192")
        return self._request(
            "GET",
            f"/api/exploration/findings/{finding_id}/traffic/{binding_id}/body"
            f"?context_task={task_id}&side={side}&offset={offset}&length={length}",
        )

    def list_goals(self, task_id: int) -> Any:
        return self._request("GET", f"/api/tasks/{int(task_id)}/goals")

    def list_constraints(self, task_id: int) -> Any:
        return self._request("GET", f"/api/tasks/{int(task_id)}/constraints")

    def list_task_scope(self, task_id: int) -> Any:
        return self._request("GET", f"/api/tasks/{int(task_id)}/scope")

    def get_task_context(self, task_id: int, *, allow_partial: bool = False) -> dict[str, Any]:
        """Read the complete native overview/preflight context in parallel.

        Preflight callers fail closed by default. The overview surface may ask
        for partial results so a missing optional endpoint does not hide the
        other visible sections from Cowork.
        """
        task_id = int(task_id)
        if task_id <= 0:
            raise ValueError("task_id must be positive")
        reads = {
            "task": lambda: self.get_task(task_id),
            "goals": lambda: self.list_goals(task_id),
            "scope": lambda: self.list_task_scope(task_id),
            "constraints": lambda: self.list_constraints(task_id),
        }
        result: dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {key: executor.submit(read) for key, read in reads.items()}
            errors = []
            for key, future in futures.items():
                try:
                    result[key] = future.result()
                except Exception as exc:
                    errors.append((key, exc))
                    result[key] = {"read_error": str(exc), "available": False}
        if errors and not allow_partial:
            details = "; ".join(f"{key}: {exc}" for key, exc in errors)
            raise ArtexAPIError(f"Could not read complete Task context: {details}") from errors[0][1]
        return result

    def add_constraint(self, task_id: int, text: str, kind: str, confirmation: str) -> Any:
        text = text.strip()
        kind = kind.strip().lower()
        if not text:
            raise ValueError("constraint text must not be empty")
        if kind not in {"allow", "deny"}:
            raise ValueError("constraint kind must be allow or deny")
        if confirmation != f"CONFIRM add_constraint task={int(task_id)}":
            raise ValueError("operation-specific constraint confirmation required")
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/constraints", {
            "text": text, "kind": kind, "confirmation": confirmation,
        })

    def add_task_scope(self, task_id: int, kind: str, value: str, confirmation: str, reason: str = "") -> Any:
        kind = kind.strip().lower()
        value = value.strip()
        allowed = {"company", "root_domain", "subdomain", "ip", "cidr", "icp", "keyword"}
        if kind not in allowed:
            raise ValueError(f"scope kind must be one of: {', '.join(sorted(allowed))}")
        if not value:
            raise ValueError("scope value must not be empty")
        if confirmation != f"CONFIRM add_scope task={int(task_id)}":
            raise ValueError("operation-specific scope confirmation required")
        return self._request(
            "POST",
            f"/api/tasks/{int(task_id)}/cowork/scope",
            {"kind": kind, "value": value, "reason": reason.strip(), "confirmation": confirmation},
        )

    def add_goal(self, task_id: int, text: str, confirmation: str, vulnclass: str = "") -> Any:
        text = text.strip()
        if not text:
            raise ValueError("goal text must not be empty")
        if confirmation != f"CONFIRM add_goal task={int(task_id)}":
            raise ValueError("operation-specific goal confirmation required")
        payload: dict[str, Any] = {"text": text}
        if vulnclass:
            payload["vulnclass"] = vulnclass
        payload["confirmation"] = confirmation
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/goals", payload)

    def manage_task_goal(self, task_id: int, goal_id: int, operation: str, confirmation: str, *, text: str = "", vulnclass: str = "") -> Any:
        task_id, goal_id = int(task_id), int(goal_id)
        if task_id <= 0 or goal_id <= 0 or operation not in {"update", "delete"}:
            raise ValueError("invalid task goal operation")
        expected = task_setup_confirmation(task_id, f"{operation}_goal", object_id=goal_id, text=text, vulnclass=vulnclass)
        if confirmation != expected:
            raise ValueError(f"operation-specific confirmation required: {expected}")
        payload: dict[str, Any] = {"operation": operation, "confirmation": confirmation}
        if operation == "update":
            text = text.strip()
            if not text:
                raise ValueError("goal text must not be empty")
            payload.update({"text": text, "vulnclass": vulnclass.strip()})
        return self._request("POST", f"/api/tasks/{task_id}/cowork/goals/{goal_id}", payload)

    def manage_task_constraint(self, task_id: int, constraint_id: int, operation: str, confirmation: str, *, kind: str = "", text: str = "") -> Any:
        task_id, constraint_id = int(task_id), int(constraint_id)
        if task_id <= 0 or constraint_id <= 0 or operation not in {"update", "delete"}:
            raise ValueError("invalid task constraint operation")
        expected = task_setup_confirmation(task_id, f"{operation}_constraint", object_id=constraint_id, kind=kind, text=text)
        if confirmation != expected:
            raise ValueError(f"operation-specific confirmation required: {expected}")
        payload: dict[str, Any] = {"operation": operation, "confirmation": confirmation}
        if operation == "update":
            kind, text = kind.strip().lower(), text.strip()
            if kind not in {"allow", "deny"} or not text:
                raise ValueError("constraint update requires allow/deny and non-empty text")
            payload.update({"kind": kind, "text": text})
        return self._request("POST", f"/api/tasks/{task_id}/cowork/constraints/{constraint_id}", payload)

    def delete_task_scope(self, task_id: int, scope_id: int, confirmation: str) -> Any:
        task_id, scope_id = int(task_id), int(scope_id)
        if task_id <= 0 or scope_id <= 0:
            raise ValueError("task_id and scope_id must be positive")
        expected = task_setup_confirmation(task_id, "delete_scope", object_id=scope_id)
        if confirmation != expected:
            raise ValueError(f"operation-specific confirmation required: {expected}")
        return self._request("DELETE", f"/api/tasks/{task_id}/cowork/scope/{scope_id}", {"confirmation": confirmation})

    def manage_task_intercept_rule(
        self, task_id: int, operation: str, confirmation: str, *, rule_id: int = 0,
        enabled: bool = True, action: str = "block", kind: str = "", pattern: str = "", note: str = "",
    ) -> Any:
        """Apply one explicitly confirmed operation to one task-owned intercept rule."""
        task_id = int(task_id)
        if task_id <= 0:
            raise ValueError("task_id must be positive")
        if operation not in {"create", "update", "delete", "toggle"}:
            raise ValueError("operation must be create, update, delete, or toggle")
        if operation != "create" and int(rule_id) <= 0:
            raise ValueError("rule_id must be positive for update, delete, or toggle")
        if operation == "delete":
            expected = task_intercept_rule_confirmation(task_id, operation, rule_id=rule_id)
            if confirmation != expected:
                raise ValueError(f"operation-specific confirmation required: {expected}")
        elif operation == "toggle":
            expected = task_intercept_rule_confirmation(task_id, operation, rule_id=rule_id, enabled=enabled)
            if confirmation != expected:
                raise ValueError(f"operation-specific confirmation required: {expected}")
        else:
            if action not in {"block", "allow"}:
                raise ValueError("action must be block or allow")
            if kind not in {"exact_domain", "exact_ip", "exact_url", "fuzzy_domain", "fuzzy_ip", "fuzzy_url", "cidr"}:
                raise ValueError("unsupported intercept rule kind")
            pattern = pattern.strip()
            if not pattern or len(pattern) > 2048:
                raise ValueError("pattern must be non-empty and at most 2048 characters")
            note = note.strip()[:500]
        expected = task_intercept_rule_confirmation(
            task_id, operation, rule_id=rule_id, enabled=enabled, action=action,
            kind=kind, pattern=pattern, note=note,
        )
        if confirmation != expected:
            raise ValueError(f"operation-specific payload confirmation required: {expected}")
        response = self._request("POST", f"/api/tasks/{task_id}/cowork/intercept-rules", {
            "operation": operation, "rule_id": int(rule_id), "confirmation": confirmation,
            "enabled": bool(enabled), "action": action, "kind": kind,
            "pattern": pattern.strip(), "note": note.strip()[:500],
        })
        if isinstance(response, dict) and isinstance(response.get("result"), dict):
            result = dict(response["result"])
            result["activity_updated"] = response.get("activity_updated")
            result["activity_error"] = response.get("activity_error", "")
            result["activity_tool_use_id"] = response.get("activity_tool_use_id", "")
            return result
        return response

    def record_task_fact(self, task_id: int, summary: str, detail: str, evidence: str, confidence: str, target: str, confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/facts", {
            "summary": summary, "detail": detail, "evidence": evidence,
            "confidence": confidence, "target": target, "confirmation": confirmation,
        })

    def prove_task_goal(self, task_id: int, goal_id: int, evidence_id: int, target: str, reason: str, confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/goals/{int(goal_id)}/prove", {
            "evidence_id": int(evidence_id), "target": target, "reason": reason,
            "confirmation": confirmation,
        })

    def pause_task(self, task_id: int, confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/pause", {
            "confirmation": confirmation,
        })

    def report_confirmed_finding(self, task_id: int, vulnclass: str, name: str, severity: str, summary: str, evidence: str, target: str, confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/findings", {
            "vulnclass": vulnclass, "name": name, "severity": severity,
            "summary": summary, "evidence": evidence, "target": target, "confirmation": confirmation,
        })

    def update_cowork_finding_status(self, task_id: int, finding_id: int, status: str, confirmation: str) -> Any:
        return self._request("PATCH", f"/api/tasks/{int(task_id)}/cowork/findings/{int(finding_id)}/status", {
            "status": status, "confirmation": confirmation,
        })

    def update_finding_report(self, task_id: int, finding_node_id: int, report: str, confirmation: str, evidence_version: int | None = None) -> Any:
        payload: dict[str, Any] = {"report": report, "confirmation": confirmation}
        if evidence_version is not None:
            payload["evidence_version"] = int(evidence_version)
        return self._request("PUT", f"/api/tasks/{int(task_id)}/cowork/findings/{int(finding_node_id)}/report", payload)

    def get_cowork_finding_report(self, task_id: int, finding_node_id: int) -> Any:
        """Read a task-local finding report by its native graph node ID."""
        return self._request("GET", f"/api/tasks/{int(task_id)}/cowork/findings/{int(finding_node_id)}/report")

    def record_cowork_finding_retest(self, task_id: int, finding_id: int, target: str, verdict: str, summary: str, evidence: str, confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/retests", {
            "finding_id": int(finding_id), "target": target, "verdict": verdict,
            "summary": summary, "evidence": evidence, "confirmation": confirmation,
        })

    def decide_cowork_intercept(self, task_id: int, pending_id: int, decision: str, confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/intercepts/{int(pending_id)}/decide", {
            "decision": decision, "confirmation": confirmation,
        })

    def add_cowork_intents(self, task_id: int, intents: list[dict[str, Any]], confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/intents", {
            "intents": intents, "confirmation": confirmation,
        })

    def complete_cowork_intent(self, task_id: int, intent_id: int, state: str, summary: str, evidence: str, confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/intents/{int(intent_id)}/complete", {
            "state": state, "summary": summary, "evidence": evidence,
            "confirmation": confirmation,
        })

    def register_cowork_assets(self, task_id: int, target: str, assets: list[dict[str, Any]], confirmation: str) -> Any:
        return self._request("POST", f"/api/tasks/{int(task_id)}/cowork/assets", {
            "target": target, "assets": assets, "confirmation": confirmation,
        })

    def write_workspace_file(self, path: str, content: str) -> Any:
        # ARTEx validates workspace paths server-side. No arbitrary filesystem path
        # is accepted here; `path` is always relative to ARTEx's workspace root.
        relative = self._workspace_relative(path)
        return self._request("POST", "/api/workspace/write", {"path": str(relative), "content": content})

    @staticmethod
    def _workspace_relative(path: str) -> PurePosixPath:
        normalized = path.replace("\\", "/")
        relative = PurePosixPath(normalized)
        raw_parts = normalized.split("/")
        if (
            relative.is_absolute()
            or not relative.parts
            or "\x00" in normalized
            or any(part in {"", ".", ".."} for part in raw_parts)
            or any(":" in part for part in relative.parts)
        ):
            raise ValueError("workspace path must be a normalized relative path without parent traversal")
        return relative

    def read_workspace_file(self, path: str) -> Any:
        relative = self._workspace_relative(path)
        return self._request("GET", f"/api/workspace/read?path={quote(str(relative), safe='')}")

    def read_task_workspace_file(self, task_id: int, path: str) -> Any:
        relative = self._workspace_relative(path)
        prefix = f"tasks/{int(task_id)}/"
        if not str(relative).startswith(prefix):
            raise ValueError(f"workspace reads are limited to {prefix}...")
        return self._request("GET", f"/api/workspace/read?path={quote(str(relative), safe='')}")

    def get_task_surface(
        self, task_id: int, surface: str, *, session: str = "main", finding_id: int = 0,
        page: int = 1, size: int = 50, before: int = 0,
    ) -> Any:
        """Read one named native ARTEx task-detail surface; never accepts a URL/path."""
        task_id = int(task_id)
        if task_id <= 0:
            raise ValueError("task_id must be positive")
        page = max(1, int(page))
        # Activity history supports a 500-row server cap; keep other tab APIs
        # at their smaller bounded page size.
        size = min(500 if surface == "session_history" else 200, max(1, int(size)))
        if surface == "overview":
            return self.get_task_context(task_id, allow_partial=True)
        if surface == "records":
            return self.get_task_records(task_id, page=page, size=size)
        if surface == "sessions":
            path = f"/api/exploration/main-sessions?task={task_id}"
        elif surface == "intents":
            # Native Worker-session index. Returned intent IDs map to
            # session_history keys `intent:<id>`.
            if page != 1:
                raise ValueError("intents uses the before cursor for pagination; page must remain 1")
            path = (
                f"/api/exploration/intents?task={task_id}"
                f"&limit={size}&page=1&before={max(0, int(before))}"
            )
        elif surface == "exploration":
            path = f"/api/exploration/graph?task={task_id}"
        elif surface == "broadcast":
            path = f"/api/exploration/nodes?task={task_id}&page={page}&size={size}"
        elif surface == "activity":
            path = f"/api/exploration/activity?task={task_id}&since={max(0, int(before))}&limit={size}"
        elif surface == "session_history":
            session = self._normalize_session_key(session)
            safe_session = quote(session, safe="")
            path = f"/api/exploration/activity/history?task={task_id}&session={safe_session}&limit={size}"
            if before > 0:
                path += f"&before={int(before)}"
        elif surface == "findings":
            path = f"/api/exploration/findings?task={task_id}"
        elif surface == "retests":
            if int(finding_id) <= 0:
                raise ValueError("finding_id must be positive for retests")
            finding = self.get_finding(int(finding_id), task_id)
            if not finding:
                raise ArtexAPIError("finding does not belong to the requested task")
            path = f"/api/exploration/findings/{int(finding_id)}/retests"
        elif surface == "assets":
            path = f"/api/assets?task_id={task_id}&limit={size}&offset={(page - 1) * size}"
        elif surface == "coverage":
            path = f"/api/tasks/{task_id}/coverage"
        elif surface == "coverage_graph":
            path = f"/api/tasks/{task_id}/coverage-graph"
        elif surface == "intercept_approvals":
            path = f"/api/intercept/task/{task_id}?page={page}&size={size}"
        elif surface == "intercept_rules":
            # Rules are separate from pending approval decisions. Expose only
            # the task-scoped read endpoint through this surface.
            path = f"/api/tasks/{task_id}/intercept-rules"
        elif surface == "report":
            native: Any = None
            native_error: str | None = None
            try:
                native = self._request("GET", f"/api/report?task={task_id}")
            except Exception as exc:
                native_error = str(exc)
            cowork_report: Any = None
            cowork_error: str | None = None
            try:
                cowork_report = self.read_task_workspace_file(
                    task_id, f"tasks/{task_id}/reports/cowork-report.md"
                )
            except ArtexAPIError as exc:
                if re.search(r"\bHTTP 404:", str(exc)):
                    cowork_report = {"content": "", "missing": True}
                else:
                    cowork_error = str(exc)
            return {
                "native": native,
                "cowork": cowork_report,
                "native_read_error": native_error,
                "cowork_read_error": cowork_error,
            }
        else:
            raise ValueError("unsupported task surface")
        return self._request("GET", path)

    def get_activity_detail(self, task_id: int, seq: int) -> dict[str, Any]:
        """Read one task-owned activity detail blob by its sequence ID."""
        task_id = int(task_id)
        seq = int(seq)
        if task_id <= 0 or seq <= 0:
            raise ValueError("task_id and activity seq must be positive integers")
        return self._request("GET", f"/api/exploration/activity/{seq}?task={task_id}")

    def get_task_records(self, task_id: int, *, page: int = 1, size: int = 50) -> dict[str, Any]:
        """Match Task detail → Records: graph facts, evidence files, and task-owned Cowork traffic metadata."""
        task_id = int(task_id)
        if task_id <= 0:
            raise ValueError("task_id must be positive")
        page = max(1, int(page))
        size = min(100, max(1, int(size)))
        graph_path = f"/api/exploration/graph?task={task_id}"
        files_path = f"/api/workspace/list?path={quote(f'tasks/{task_id}/evidence', safe='')}"
        traffic_path = f"/api/tasks/{task_id}/cowork/traffic?page={page - 1}&size={size}"
        with ThreadPoolExecutor(max_workers=3) as executor:
            graph_future = executor.submit(self._request, "GET", graph_path)
            files_future = executor.submit(self._request, "GET", files_path)
            traffic_future = executor.submit(self._request, "GET", traffic_path)
            try:
                graph = graph_future.result()
                nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
                facts = [node for node in nodes if isinstance(node, dict) and node.get("type") == "fact" and node.get("state") != "origin"]
                facts.reverse()
            except Exception as exc:
                facts = []
                facts_error = {"read_error": str(exc), "available": False}
            else:
                facts_error = None
            try:
                listing = files_future.result()
                entries = listing.get("entries", []) if isinstance(listing, dict) else []
                files = [entry for entry in entries if isinstance(entry, dict) and not entry.get("dir")]
                files.sort(key=lambda entry: entry.get("mtime", 0), reverse=True)
            except Exception as exc:
                # A new Task may not have an evidence directory yet. That is
                # an empty Records surface, not a failed read. Preserve real
                # authorization/server/network failures for the UI and writers.
                if isinstance(exc, ArtexAPIError) and re.search(r"\bHTTP 404:", str(exc)):
                    files = []
                    files_error = None
                else:
                    files = []
                    files_error = {"read_error": str(exc), "available": False}
            else:
                files_error = None
            try:
                traffic = traffic_future.result()
            except Exception as exc:
                traffic = {"enabled": False, "total": 0, "exchanges": []}
                traffic_error = {"read_error": str(exc), "available": False}
            else:
                traffic_error = None
        return {
            "facts": facts,
            "files": files,
            "traffic": traffic,
            "facts_error": facts_error,
            "files_error": files_error,
            "traffic_error": traffic_error,
        }

    def list_cowork_traffic(self, task_id: int, *, page: int = 0, size: int = 50) -> Any:
        """List metadata for native Traffic exchanges captured by this Cowork task only."""
        task_id = int(task_id)
        page = int(page)
        size = int(size)
        if task_id <= 0 or not 0 <= page <= 1_000_000 or not 1 <= size <= 100:
            raise ValueError("task_id must be positive, page between 0 and 1000000, and size between 1 and 100")
        return self._request(
            "GET", f"/api/tasks/{task_id}/cowork/traffic?page={page}&size={size}"
        )

    def get_cowork_traffic(self, task_id: int, capture_id: str) -> Any:
        """Read one full exchange after validating its stable ID is task-bound."""
        task_id = int(task_id)
        if task_id <= 0 or not isinstance(capture_id, str):
            raise ValueError("task_id must be positive and capture_id must be a string")
        if not re.fullmatch(rf"cowork-t{task_id}-[a-f0-9]{{32}}-[1-9][0-9]*", capture_id):
            raise ValueError("capture_id must belong to the requested task")
        return self._request(
            "GET", f"/api/tasks/{task_id}/cowork/traffic/{quote(capture_id, safe='')}"
        )

    def read_cowork_traffic_blob(
        self, task_id: int, capture_id: str, blob_hash: str, *, offset: int = 0, length: int = 8192,
    ) -> Any:
        """Read a bounded body chunk only when that blob belongs to the task capture."""
        task_id = int(task_id)
        offset = int(offset)
        length = int(length)
        if task_id <= 0 or offset < 0 or not 1 <= length <= 8192:
            raise ValueError("task_id must be positive, offset non-negative, and length between 1 and 8192")
        if not isinstance(capture_id, str) or not re.fullmatch(rf"cowork-t{task_id}-[a-f0-9]{{32}}-[1-9][0-9]*", capture_id):
            raise ValueError("capture_id must belong to the requested task")
        if not isinstance(blob_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", blob_hash):
            raise ValueError("blob_hash must be a SHA-256 hex value")
        query = f"hash={quote(blob_hash, safe='')}&offset={offset}&length={length}"
        return self._request(
            "GET", f"/api/tasks/{task_id}/cowork/traffic/{quote(capture_id, safe='')}/blob?{query}"
        )

    @staticmethod
    def _normalize_session_key(session: str) -> str:
        """Accept only ARTEx session identifiers, including the distinct Cowork activity stream."""
        if not isinstance(session, str):
            raise ValueError("session must be main, main:<segment>, plan, cowork, or intent:<id>")
        if session in {"main", "plan", "cowork"}:
            return session
        if re.fullmatch(r"main:(?:0|[1-9][0-9]{0,8})", session):
            return session
        match = re.fullmatch(r"intent:([1-9][0-9]{0,17})", session)
        if match:
            return session
        raise ValueError("session must be main, main:<segment>, plan, cowork, or intent:<positive intent id>")

    def get_task_surface_bundle(self, task_id: int, *, session: str = "main", finding_id: int = 0) -> dict[str, Any]:
        """Read all broadly available task-detail surfaces in one client operation.

        Retests are included only when a same-task finding ID is supplied. The
        Cowork-originated activity ledger is returned separately from main-agent
        session history. Each surface reports its own error so an optional ARTEx
        endpoint cannot hide successful results from the other tabs.
        """
        task_id = int(task_id)
        if task_id <= 0:
            raise ValueError("task_id must be positive")
        results: dict[str, Any] = {}
        # One Cowork call fans out to a bounded number of independent GETs so a
        # slow optional tab does not make the whole snapshot wait sequentially.
        with ThreadPoolExecutor(max_workers=min(6, len(TASK_DETAIL_SURFACES))) as executor:
            futures = {
                surface: executor.submit(self.get_task_surface, task_id, surface, session=session)
                for surface in TASK_DETAIL_SURFACES
            }
            # Cowork-originated ARTEx writes are an explicit activity ledger, not
            # a main-agent transcript. Include that stream separately in bundles.
            futures["cowork_activity"] = executor.submit(
                self.get_task_surface, task_id, "session_history", session="cowork"
            )
            for surface, future in futures.items():
                try:
                    results[surface] = future.result()
                except Exception as exc:  # preserve partial results across endpoint/version skew
                    results[surface] = {"read_error": str(exc), "available": False}
        if finding_id > 0:
            try:
                results["retests"] = self.get_task_surface(task_id, "retests", finding_id=finding_id)
            except Exception as exc:
                results["retests"] = {"read_error": str(exc), "available": False}
        else:
            results["retests"] = {"skipped": "finding_id not supplied"}
        return {"task_id": task_id, "read_only": True, "surfaces": results}

    def clear_token(self) -> None:
        self._token = None
