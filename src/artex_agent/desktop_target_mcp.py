"""Bounded target-request bridge for an explicitly authorized Cowork run.

This server is intentionally separate from ARTEx's own LLM engine. It sends
only requests to an origin covered by the selected ARTEx task's scope and
human allow constraint, honors deny constraints, and keeps a per-process run
budget. A process restart discards the run and therefore fails closed.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
import uuid
from http.cookiejar import CookieJar
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from mcp.server.fastmcp import FastMCP

from .artex_api import ArtexClient
from .desktop_diagnostic_writer import _authenticated_client, _target_parts, _verify_context


server = FastMCP("artex-target-request")
_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE"}
_TEST_CLASSES = {
    "passive_recon", "authentication", "session_management", "cors",
    "method_handling", "error_handling", "cache", "transport_security",
    "input_reflection", "injection", "xss_csrf", "client_tampering",
    "account_policy", "access_control", "information_disclosure",
    "file_exposure", "directory_indexing", "security_headers",
    "search_engine_exposure", "firewall_policy",
}
_CLASS_METHODS = {
    "passive_recon": {"GET", "HEAD", "OPTIONS"},
    "authentication": {"GET", "POST"},
    "session_management": {"GET", "POST"},
    "cors": {"GET", "HEAD", "OPTIONS", "POST"},
    "method_handling": _METHODS,
    "error_handling": {"GET", "HEAD", "POST"},
    "cache": {"GET", "HEAD"},
    "transport_security": {"GET", "HEAD"},
    "input_reflection": {"GET", "POST"},
    "injection": {"GET", "POST"},
    "xss_csrf": {"GET", "POST"},
    "client_tampering": {"GET", "POST", "PATCH"},
    "account_policy": {"GET", "POST"},
    "access_control": {"GET", "POST", "PATCH", "DELETE"},
    "information_disclosure": {"GET", "HEAD", "OPTIONS"},
    "file_exposure": {"GET", "HEAD"},
    "directory_indexing": {"GET", "HEAD"},
    "security_headers": {"GET", "HEAD", "OPTIONS"},
    "search_engine_exposure": {"GET", "HEAD"},
    "firewall_policy": {"GET", "HEAD", "OPTIONS"},
}
_MAX_RUN_REQUESTS = 500
_MAX_RESPONSE_BYTES = 2_000_000
_MAX_BATCH_RESPONSE_TEXT = 64_000
_MAX_BODY_BYTES = 64_000
_MAX_BATCH_REQUESTS = 20
_MAX_RUN_SECONDS = 4 * 60 * 60
_runs: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_request_lock = threading.Lock()
_last_request_at = 0.0


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _origin(value: str) -> tuple[str, str, str]:
    host, authority, origin = _target_parts(value)
    parsed = urlsplit(value.strip())
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("target_origin must be an HTTP(S) origin without path, query, or fragment")
    return host, authority, origin


def _verify_target_allow(client: ArtexClient, task_id: int, target_origin: str) -> None:
    _verify_context(client, task_id, target_origin)


def _request_url(origin: str, path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or len(path) > 4096:
        raise ValueError("path must be a local absolute path beginning with one slash")
    if "#" in path or "\\" in path or any(ord(ch) < 0x20 for ch in path):
        raise ValueError("path contains a fragment, backslash, or control character")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("path must not contain an origin or fragment")
    return origin.rstrip("/") + path


def _clear_session(run: dict[str, Any]) -> None:
    run["cookie_jar"] = None
    run["bearer_token"] = None


def _stop_run(run: dict[str, Any], reason: str) -> None:
    run["stopped"] = True
    run["stop_reason"] = run["stop_reason"] or reason
    stop_event = run.get("stop_event")
    if stop_event is not None:
        stop_event.set()
    _clear_session(run)


def _validated_headers(headers_json: str) -> dict[str, str]:
    if not isinstance(headers_json, str) or len(headers_json.encode("utf-8")) > 12_000:
        raise ValueError("headers_json must be no larger than 12000 UTF-8 bytes")
    try:
        headers = json.loads(headers_json)
    except json.JSONDecodeError as exc:
        raise ValueError("headers_json must be a JSON object") from exc
    if not isinstance(headers, dict) or len(headers) > 20:
        raise ValueError("headers_json must be an object containing at most 20 headers")
    forbidden = {"host", "cookie", "authorization", "proxy-authorization", "connection", "content-length", "transfer-encoding", "set-cookie"}
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}", name):
            raise ValueError("header name is invalid")
        if name.lower() in forbidden or re.search(r"(?i)(?:auth|token|secret|api.?key|cookie)", name):
            raise ValueError(f"header {name!r} cannot be set by Cowork")
        if not isinstance(value, str) or len(value) > 2048 or any(ord(ch) < 0x20 and ch != "\t" for ch in value) or "\x7f" in value:
            raise ValueError(f"header {name!r} value is invalid or too long")
        normalized[name] = value
    return normalized


def _confirmation(task_id: int, origin: str, count: int, methods: list[str], rate: int, test_classes: list[str], session_mode: str, record_traffic: bool) -> str:
    return (
        f"CONFIRM authorize_target_run task={task_id} origin={origin} "
        f"max_requests={count} methods={','.join(methods)} requests_per_minute={rate} "
        f"test_classes={','.join(test_classes)} session_mode={session_mode} "
        f"record_traffic={'yes' if record_traffic else 'no'}"
    )


def _find_access_token(value: Any) -> str | None:
    """Keep a same-origin login token in memory without returning it to Cowork."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized in {"token", "accesstoken", "authtoken", "jwt", "idtoken"} and isinstance(child, str):
                if 12 <= len(child) <= 8192 and re.fullmatch(r"[A-Za-z0-9._~+/=-]+", child):
                    return child
            found = _find_access_token(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_access_token(child)
            if found:
                return found
    return None


def _redacted_url(url: str) -> str:
    parts = urlsplit(url)
    secret_names = {
        "password", "passwd", "token", "accesstoken", "refreshtoken", "apikey", "key", "secret", "code",
        "auth", "authorization", "session", "sessionid", "csrf", "csrftoken", "jwt", "nonce",
        "credential", "clientsecret", "samlresponse", "assertion", "state", "ticket",
        "email", "user", "username", "userid", "account", "accountid", "accountname",
        "login", "member", "memberid", "phone", "telephone", "tel", "mobile", "address",
        "fullname", "firstname", "lastname", "dateofbirth", "birthdate", "dob",
    }
    query = urlencode([
        (key, "[REDACTED]" if re.sub(r"[^a-z0-9]", "", key.lower()) in secret_names else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ])
    path = re.sub(r"(?i)/(reset|verify|token|invite)/[^/?#]{8,}", r"/\1/[REDACTED]", parts.path)
    return urlunsplit((parts.scheme, parts.netloc, path, query, ""))


def _redacted_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = dict(headers)
    personal_name_parts = (
        "user", "account", "login", "member", "email", "phone", "mobile",
        "telephone", "address", "fullname", "firstname", "lastname", "dateofbirth", "birthdate", "dob",
    )
    for name in list(redacted):
        normalized = re.sub(r"[^a-z0-9]", "", name.lower())
        if re.search(r"(?i)(?:auth|cookie|token|secret|api.?key|session|password|credential)", name) or any(
            part in normalized for part in personal_name_parts
        ):
            redacted[name] = "[REDACTED]"
    if "location" in redacted:
        redacted["location"] = _redacted_url(redacted["location"])
    return redacted


def _sensitive_request_values(body: str) -> set[str]:
    values: set[str] = set()
    secret_key = re.compile(r"(?i)(?:password|passwd|token|secret|credential|authorization|cookie|email|user(?:name|_?id)?|login|account(?:name|_?id)?|phone|mobile|address)")
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        parsed = None

    def collect(item: Any, key: str = "") -> None:
        if isinstance(item, dict):
            for child_key, child in item.items():
                collect(child, str(child_key))
        elif isinstance(item, list):
            for child in item:
                collect(child, key)
        elif key and secret_key.search(key) and isinstance(item, (str, int, float)):
            value = str(item)
            if len(value) >= 3:
                values.add(value)

    collect(parsed)
    for key, value in parse_qsl(body, keep_blank_values=True):
        if secret_key.search(key) and len(value) >= 3:
            values.add(value)
    for match in re.finditer(r"(?i)(?:password|passwd|token|secret|email|username|user_id|phone)\s*[:=]\s*[\"']?([^&\s,;\"'}]+)", body):
        if len(match.group(1)) >= 3:
            values.add(match.group(1))
    return values


def _redacted_body(raw: bytes, sensitive_values: set[str] | None = None) -> str:
    text = raw[:_MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        value = None
    if value is not None:
        secret_names = {
            re.sub(r"[^a-z0-9]", "", name)
            for name in (
                "password", "passwd", "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
                "authorization", "cookie", "email", "user", "username", "user_id", "login", "account",
                "account_id", "account_name", "member", "member_id", "credential", "phone", "telephone",
                "mobile", "address", "full_name", "first_name", "last_name", "date_of_birth", "birthdate", "dob",
            )
        }

        def is_secret_name(name: Any) -> bool:
            normalized = re.sub(r"[^a-z0-9]", "", str(name).lower())
            return (
                normalized in secret_names
                or normalized.endswith("token")
                or normalized.endswith("secret")
                or normalized.endswith("email")
                or normalized.endswith("phone")
            )

        def redact(item):
            if isinstance(item, dict):
                return {
                    key: "[REDACTED]" if is_secret_name(key) else redact(child)
                    for key, child in item.items()
                }
            if isinstance(item, list):
                return [redact(child) for child in item]
            return item

        text = json.dumps(redact(value), ensure_ascii=False)
    else:
        text = re.sub(r"(?i)(\b(?:password|passwd|token|jwt|access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|authorization|cookie)\b\s*[:=]\s*[\"']?)[^\s,;\"'}]+", r"\1[REDACTED]", text)
        text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", "Bearer [REDACTED]", text)
        text = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[JWT REDACTED]", text)
    text = re.sub(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[EMAIL REDACTED]", text)
    for value in sorted(sensitive_values or (), key=len, reverse=True):
        text = text.replace(value, "[REQUEST VALUE REDACTED]")
    return text


@server.tool()
def artex_begin_target_run(
    task_id: int,
    target_origin: str,
    max_requests: int,
    allowed_methods: str,
    requests_per_minute: int,
    allowed_test_classes: str,
    session_mode: str,
    record_traffic: bool,
    confirmation: str,
) -> str:
    """Start an in-memory request budget after the operator authorizes the exact run.

    This does not send a target request. record_traffic explicitly authorizes
    storing full completed exchanges in native ARTEx Traffic and is included in
    the exact confirmation. allowed_methods is a comma-separated list from
    GET, HEAD, OPTIONS, TRACE, POST, PUT, PATCH, DELETE. Session mode is none,
    cookies, or cookies_and_bearer. The confirmation binds all run settings.
    Session values remain in process memory and are never returned by a tool.
    Test classes are passive_recon, authentication, session_management, cors,
    method_handling, error_handling, cache, transport_security,
    input_reflection, injection, xss_csrf, client_tampering, account_policy,
    access_control, information_disclosure, file_exposure, directory_indexing,
    security_headers, search_engine_exposure, and firewall_policy. Each class
    constrains methods independently of the run's authorized method ceiling.
    """
    if not isinstance(task_id, int) or task_id <= 0:
        raise ValueError("task_id must be a positive integer")
    if not isinstance(max_requests, int) or not 1 <= max_requests <= _MAX_RUN_REQUESTS:
        raise ValueError(f"max_requests must be between 1 and {_MAX_RUN_REQUESTS}")
    if not isinstance(requests_per_minute, int) or not 1 <= requests_per_minute <= 60:
        raise ValueError("requests_per_minute must be between 1 and 60")
    if not isinstance(allowed_test_classes, str):
        raise ValueError("allowed_test_classes must be a comma-separated string")
    test_classes = sorted({item.strip().lower() for item in allowed_test_classes.split(",") if item.strip()})
    if not test_classes or set(test_classes) - _TEST_CLASSES:
        raise ValueError(f"allowed_test_classes must use: {', '.join(sorted(_TEST_CLASSES))}")
    if session_mode not in {"none", "cookies", "cookies_and_bearer"}:
        raise ValueError("session_mode must be none, cookies, or cookies_and_bearer")
    _, _, origin = _origin(target_origin)
    if not isinstance(allowed_methods, str):
        raise ValueError("allowed_methods must be a comma-separated string")
    methods = sorted({item.strip().upper() for item in allowed_methods.split(",") if item.strip()})
    if not methods or set(methods) - _METHODS:
        raise ValueError("allowed_methods must contain only supported HTTP methods")
    if not isinstance(record_traffic, bool):
        raise ValueError("record_traffic must be true or false")
    expected = _confirmation(task_id, origin, max_requests, methods, requests_per_minute, test_classes, session_mode, record_traffic)
    if confirmation != expected:
        raise ValueError(f"operator authorization required: confirmation={expected!r}")

    client = _authenticated_client()
    try:
        _verify_target_allow(client, task_id, origin)
    finally:
        client.clear_token()

    run_id = uuid.uuid4().hex
    with _lock:
        expired = [
            key for key, value in _runs.items()
            if value["stopped"] or time.monotonic() - value["started_at"] > _MAX_RUN_SECONDS
        ]
        for key in expired:
            _stop_run(_runs[key], "run expired")
            _runs.pop(key, None)
        if len(_runs) >= 128:
            raise RuntimeError("too many live target runs; finish or let an existing run expire")
        _runs[run_id] = {
            "task_id": task_id,
            "origin": origin,
            "methods": methods,
            "test_classes": test_classes,
            "max_requests": max_requests,
            "requests_per_minute": requests_per_minute,
            "session_mode": session_mode,
            "record_traffic": record_traffic,
            "cookie_jar": CookieJar() if session_mode in {"cookies", "cookies_and_bearer"} else None,
            "bearer_token": None,
            "started_at": time.monotonic(),
            "count": 0,
            "stopped": False,
            "stop_reason": None,
            "stop_event": threading.Event(),
            "request_in_flight": False,
        }
    return json.dumps({
        "ok": True,
        "run_id": run_id,
        "task_id": task_id,
        "origin": origin,
        "allowed_methods": methods,
        "allowed_test_classes": test_classes,
        "request_budget": max_requests,
        "requests_per_minute": requests_per_minute,
        "session_mode": session_mode,
        "record_traffic": record_traffic,
        "stop_conditions": ["redirect", "HTTP 429", "any 5xx", "request timeout over 8 seconds", "response over 2 MB", "ARTEx Traffic recording failure when enabled"],
        "target_requests_sent": 0,
    }, ensure_ascii=False)


def _send_target_request_impl(
    run_id: str,
    test_class: str,
    method: str,
    path: str,
    body: str = "",
    content_type: str = "application/json",
    headers_json: str = "{}",
    response_output_limit: int = _MAX_RESPONSE_BYTES,
) -> str:
    """Send one bounded request inside a live, explicitly authorized target run.

    Caller-supplied credential headers are rejected. Same-origin cookies and a
    response token are reused only when the run confirmation enables them. A
    redirect, 429, 5xx, timeout, or oversized response closes the run.
    """
    global _last_request_at
    method = method.strip().upper() if isinstance(method, str) else ""
    test_class = test_class.strip().lower() if isinstance(test_class, str) else ""
    if test_class not in _TEST_CLASSES:
        raise ValueError("unsupported test_class")
    if method not in _METHODS:
        raise ValueError("unsupported HTTP method")
    if not isinstance(body, str) or len(body.encode("utf-8")) > _MAX_BODY_BYTES:
        raise ValueError(f"body must be no larger than {_MAX_BODY_BYTES} UTF-8 bytes")
    if not isinstance(content_type, str) or not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]{1,80}/[A-Za-z0-9!#$&^_.+-]{1,80}(?:\s*;[^\r\n]{0,200})?", content_type):
        raise ValueError("content_type is invalid")
    extra_headers = _validated_headers(headers_json)
    with _lock:
        run = _runs.get(run_id)
        if not run:
            raise ValueError("run_id is missing, expired, or belongs to another MCP process")
        if run["stopped"]:
            raise ValueError(f"run is stopped: {run['stop_reason']}")
        if method not in run["methods"]:
            raise ValueError("HTTP method was not included in this run authorization")
        if test_class not in run["test_classes"]:
            raise ValueError("test_class was not included in this run authorization")
        if method not in _CLASS_METHODS[test_class]:
            raise ValueError(f"HTTP method {method} is not valid for test_class {test_class}")
        if run["count"] >= run["max_requests"]:
            _stop_run(run, "request budget exhausted")
            raise ValueError("run request budget exhausted")
        if time.monotonic() - run["started_at"] > _MAX_RUN_SECONDS:
            _stop_run(run, "maximum run duration exceeded")
            raise ValueError("run expired")
        floor = 60.0 / run["requests_per_minute"]
        wait_for = floor - (time.monotonic() - _last_request_at)
        stop_event = run["stop_event"]
        url = _request_url(run["origin"], path)

    # Do not hold the state lock while rate-limiting. Closing the run sets this
    # event directly, so a long configured interval is interruptible.
    if wait_for > 0 and stop_event.wait(wait_for):
        raise ValueError("run was closed during rate-limit wait")
    if stop_event.is_set():
        raise ValueError("run was closed before request transmission")
    with _lock:
        run = _runs.get(run_id)
        if not run or run["stopped"]:
            raise ValueError("run was closed before request transmission")

    # Re-read live ARTEx authorization before each request so a newly added
    # deny or removed allow stops an already-open run before more traffic.
    client = _authenticated_client()
    try:
        _verify_target_allow(client, run["task_id"], run["origin"])
    except Exception:
        with _lock:
            _stop_run(run, "live task authorization changed or could not be verified")
        raise
    finally:
        client.clear_token()

    with _lock:
        run = _runs[run_id]
        if run["stopped"]:
            raise ValueError(f"run is stopped: {run['stop_reason']}")
        if run["count"] >= run["max_requests"]:
            _stop_run(run, "request budget exhausted")
            raise ValueError("run request budget exhausted")
        _last_request_at = time.monotonic()
        run["count"] += 1
        sequence = run["count"]
        run["request_in_flight"] = True

    headers = {"Accept": "*/*", "User-Agent": "ARTEx-Cowork/0.1", "Connection": "close"}
    headers.update(extra_headers)
    data = None
    if body:
        data = body.encode("utf-8")
        headers["Content-Type"] = content_type
    if run["session_mode"] == "cookies_and_bearer" and run["bearer_token"]:
        headers["Authorization"] = f"Bearer {run['bearer_token']}"
    request = Request(url, data=data, headers=headers, method=method)
    if run["cookie_jar"] is not None:
        run["cookie_jar"].add_cookie_header(request)
    started = time.monotonic()
    status = None
    response_headers: dict[str, str] = {}
    response_body = b""
    error = None
    try:
        handlers = [ProxyHandler({}), _NoRedirect()]
        if run["cookie_jar"] is not None:
            handlers.append(HTTPCookieProcessor(run["cookie_jar"]))
        with build_opener(*handlers).open(request, timeout=8.0) as response:
            status = response.status
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            response_body = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        status = exc.code
        response_headers = {key.lower(): value for key, value in exc.headers.items()}
        try:
            response_body = exc.read(_MAX_RESPONSE_BYTES + 1)
        except Exception as read_exc:
            error = type(read_exc).__name__
    except Exception as exc:
        error = type(exc).__name__

    with _lock:
        run = _runs.get(run_id)
        if run is not None:
            run["request_in_flight"] = False
            if run["stop_event"].is_set():
                _clear_session(run)

    elapsed_ms = round((time.monotonic() - started) * 1000)
    raw_response_headers = dict(response_headers)
    stop_reason = None
    if error is not None:
        stop_reason = f"request or response read error: {error}"
    elif status is None:
        stop_reason = f"request error: {error or 'no response'}"
    elif 300 <= status < 400:
        stop_reason = "redirect response"
    elif status == 429:
        stop_reason = "HTTP 429 rate limit"
    elif status >= 500:
        stop_reason = f"HTTP {status} server error"
    elif len(response_body) > _MAX_RESPONSE_BYTES:
        stop_reason = "response exceeded 2 MB"
    elif elapsed_ms > 8_000:
        stop_reason = "request exceeded 8 seconds"

    with _lock:
        run = _runs[run_id]
        if stop_reason:
            _stop_run(run, stop_reason)
        elif run["count"] >= run["max_requests"]:
            _stop_run(run, "request budget exhausted")
            stop_reason = run["stop_reason"]

    response_headers = _redacted_headers(response_headers)
    # A stop condition clears session state above. Never repopulate a stopped
    # run from the response that caused the stop (for example a login response
    # with a token followed by a redirect or server error).
    if run["session_mode"] == "cookies_and_bearer" and not stop_reason and not run["stop_event"].is_set():
        try:
            discovered_token = _find_access_token(json.loads(response_body.decode("utf-8", errors="strict")))
        except (UnicodeDecodeError, json.JSONDecodeError):
            discovered_token = None
        if discovered_token:
            with _lock:
                current = _runs.get(run_id)
                if current is not None and not current["stop_event"].is_set():
                    current["bearer_token"] = discovered_token
    redacted_body = _redacted_body(response_body, _sensitive_request_values(body))
    text = redacted_body[:response_output_limit]
    traffic_record = None
    if run["record_traffic"] and status is not None:
        if len(response_body) > _MAX_RESPONSE_BYTES:
            traffic_record = {"ok": False, "error": "response exceeded the traffic capture limit; not stored"}
        else:
            capture_id = f"cowork-t{run['task_id']}-{run_id}-{sequence}"
            request_headers = {key: value for key, value in request.header_items()}
            request_headers.setdefault("Host", urlsplit(url).netloc)
            try:
                client = _authenticated_client()
                try:
                    traffic_record = client.record_cowork_traffic(run["task_id"], {
                        "confirmation": f"CONFIRM record_cowork_traffic task={run['task_id']}",
                        "target": run["origin"],
                        "capture_id": capture_id,
                        "url": url,
                        "method": method,
                        "status": status,
                        "request_headers": request_headers,
                        "response_headers": raw_response_headers,
                        "request_body_b64": base64.b64encode(body.encode("utf-8")).decode("ascii"),
                        "response_body_b64": base64.b64encode(response_body).decode("ascii"),
                    })
                finally:
                    client.clear_token()
            except Exception as exc:
                traffic_record = {"ok": False, "error": type(exc).__name__}
        if not isinstance(traffic_record, dict) or traffic_record.get("ok") is not True or traffic_record.get("activity_updated") is not True:
            with _lock:
                _stop_run(run, "ARTEx Traffic recording failed or was incomplete")
    with _lock:
        run_stopped = bool(run["stopped"])
        final_stop_reason = run["stop_reason"]
    return json.dumps({
        "run_id": run_id,
        "task_id": run["task_id"],
        "sequence": sequence,
        "request": {"test_class": test_class, "method": method, "url": _redacted_url(url), "body_bytes": len(body.encode("utf-8"))},
        "session_mode": run["session_mode"],
        "response": {
            "status": status,
            "elapsed_ms": elapsed_ms,
            "headers": response_headers,
            "body_bytes": len(response_body),
            "body_truncated": len(response_body) > _MAX_RESPONSE_BYTES or len(redacted_body) > response_output_limit,
            "body": text,
        },
        "run_stopped": run_stopped,
        "stop_reason": final_stop_reason,
        "traffic_record": traffic_record,
        "remaining_requests": max(0, run["max_requests"] - sequence),
    }, ensure_ascii=False)


@server.tool()
def artex_send_target_request(
    run_id: str,
    test_class: str,
    method: str,
    path: str,
    body: str = "",
    content_type: str = "application/json",
    headers_json: str = "{}",
) -> str:
    """Send one request at a time inside an explicitly authorized target run."""
    with _request_lock:
        return _send_target_request_impl(run_id, test_class, method, path, body, content_type, headers_json)


@server.tool()
def artex_send_target_batch(run_id: str, requests_json: str) -> str:
    """Send up to 20 prevalidated requests sequentially in one Cowork tool call.

    All entries share the run's authorized methods, rate, and remaining count.
    The batch stops on its first request error or enforced stop condition. Each
    response body is redacted and capped at 64 KB in the batch result.
    """
    if not isinstance(requests_json, str) or len(requests_json.encode("utf-8")) > 250_000:
        raise ValueError("requests_json must be no larger than 250000 UTF-8 bytes")
    try:
        requests = json.loads(requests_json)
    except json.JSONDecodeError as exc:
        raise ValueError("requests_json must be a JSON array") from exc
    if not isinstance(requests, list) or not 1 <= len(requests) <= _MAX_BATCH_REQUESTS:
        raise ValueError(f"requests_json must contain 1 to {_MAX_BATCH_REQUESTS} requests")

    with _lock:
        run = _runs.get(run_id)
        if not run or run["stopped"]:
            raise ValueError("run_id is missing, expired, or stopped")
        origin = run["origin"]
        allowed_methods = set(run["methods"])
        remaining_requests = max(0, run["max_requests"] - run["count"])
        if len(requests) > remaining_requests:
            raise ValueError(
                f"batch has {len(requests)} requests but only {remaining_requests} remain; "
                "reduce the batch before sending"
            )

    normalized: list[dict[str, str]] = []
    for index, item in enumerate(requests):
        if not isinstance(item, dict) or set(item) - {"test_class", "method", "path", "body", "content_type", "headers"}:
            raise ValueError(f"requests[{index}] has an invalid shape")
        test_class = item.get("test_class")
        method = item.get("method", "GET")
        path = item.get("path")
        body = item.get("body", "")
        content_type = item.get("content_type", "application/json")
        headers_json = json.dumps(item.get("headers", {}), ensure_ascii=False)
        if not isinstance(test_class, str) or test_class.strip().lower() not in run["test_classes"]:
            raise ValueError(f"requests[{index}] test_class was not authorized for this run")
        if not isinstance(method, str) or method.strip().upper() not in allowed_methods:
            raise ValueError(f"requests[{index}] method was not authorized for this run")
        if method.strip().upper() not in _CLASS_METHODS[test_class.strip().lower()]:
            raise ValueError(f"requests[{index}] method is not valid for its test_class")
        if not isinstance(path, str):
            raise ValueError(f"requests[{index}].path must be a string")
        _request_url(origin, path)
        if not isinstance(body, str) or len(body.encode("utf-8")) > _MAX_BODY_BYTES:
            raise ValueError(f"requests[{index}].body exceeds the {_MAX_BODY_BYTES}-byte limit")
        if not isinstance(content_type, str) or not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]{1,80}/[A-Za-z0-9!#$&^_.+-]{1,80}(?:\s*;[^\r\n]{0,200})?", content_type):
            raise ValueError(f"requests[{index}].content_type is invalid")
        _validated_headers(headers_json)
        normalized.append({
            "test_class": test_class.strip().lower(), "method": method.strip().upper(), "path": path, "body": body,
            "content_type": content_type, "headers_json": headers_json,
        })

    results = []
    with _request_lock:
        # Recheck after acquiring the same lock used by single-request calls;
        # otherwise a concurrent request could consume part of the budget
        # between preflight and the first item, causing a surprising partial batch.
        with _lock:
            run = _runs.get(run_id)
            if not run or run["stopped"]:
                raise ValueError("run_id is missing, expired, or stopped")
            remaining_requests = max(0, run["max_requests"] - run["count"])
            if len(normalized) > remaining_requests:
                raise ValueError(
                    f"batch has {len(normalized)} requests but only {remaining_requests} remain; "
                    "reduce the batch before sending"
                )
        for index, item in enumerate(normalized):
            try:
                result = json.loads(_send_target_request_impl(
                    run_id, item["test_class"], item["method"], item["path"], item["body"],
                    item["content_type"], item["headers_json"], _MAX_BATCH_RESPONSE_TEXT,
                ))
            except Exception as exc:
                results.append({"batch_index": index, "sent": False, "error": str(exc)})
                break
            result["batch_index"] = index
            results.append(result)
            if result.get("run_stopped"):
                break
    return json.dumps({
        "run_id": run_id,
        "requested": len(normalized),
        "completed": sum(1 for item in results if item.get("sent", True)),
        "results": results,
        "batch_stopped": len(results) < len(normalized) or any(item.get("run_stopped") for item in results),
    }, ensure_ascii=False)


@server.tool()
def artex_close_target_run(run_id: str) -> str:
    """Stop a run immediately and return its count and in-flight request state.

    Closing interrupts rate-limit waits and blocks subsequent requests. An HTTP
    request already on the wire cannot be canceled; request_in_flight reports
    whether its response is still being collected.
    """
    with _lock:
        run = _runs.get(run_id)
        if not run:
            raise ValueError("run_id is missing, expired, or belongs to another MCP process")
        _stop_run(run, "operator closed the run")
        return json.dumps({
            "ok": True,
            "run_id": run_id,
            "task_id": run["task_id"],
            "requests_used": run["count"],
            "request_budget": run["max_requests"],
            "request_in_flight": run["request_in_flight"],
            "stop_reason": run["stop_reason"],
        }, ensure_ascii=False)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
