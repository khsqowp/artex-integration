"""Read-only ARTEx acceptance through the registered Cowork MCP tool handlers.

This avoids spawning subprocesses, which may be disabled by managed Windows
execution policy. It exercises the same FastMCP tool functions, but does not
claim to verify MCP stdio transport or a Claude Cowork account session.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from artex_agent.desktop_diagnostic_writer import server as evidence_writer
from artex_agent.desktop_mcp import server as artex_ro
from artex_agent.desktop_target_mcp import server as target_request
from artex_agent.desktop_task_setup_mcp import server as task_setup


EXPECTED_SURFACES = {
    "overview", "sessions", "intents", "exploration", "records", "activity",
    "session_history", "broadcast", "findings", "retests", "assets", "coverage",
    "coverage_graph", "intercept_approvals", "intercept_rules", "report", "cowork_activity",
}
EXPECTED_CONNECTOR_COUNTS = {
    "artex_ro": 17,
    "artex_evidence_writer": 14,
    "artex_task_setup": 5,
    "artex_target_request": 4,
}


def _decode(value: Any) -> Any:
    if isinstance(value, tuple) and len(value) == 2:
        # FastMCP returns (content blocks, structuredContent).
        return _decode(value[1])
    if isinstance(value, str):
        try:
            return _decode(json.loads(value))
        except (json.JSONDecodeError, TypeError):
            return value
    if isinstance(value, dict) and set(value) == {"result"}:
        return _decode(value["result"])
    return value


async def _call(server: Any, name: str, arguments: dict[str, Any]) -> Any:
    return _decode(await server.call_tool(name, arguments))


def _rows(value: Any, keys: tuple[str, ...]) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in keys:
            child = value.get(key)
            if isinstance(child, list):
                return child
    return []


def _collection_count(value: Any, key: str) -> int | None:
    rows = _rows(value, (key, "items", "data", "results"))
    return len(rows) if rows else (0 if isinstance(value, (list, dict)) else None)


def _finding_id(findings: Any) -> int:
    for row in _rows(findings, ("findings", "items", "data", "results")):
        if not isinstance(row, dict):
            continue
        value = row.get("finding_id") or row.get("findingId")
        try:
            result = int(value)
        except (TypeError, ValueError):
            continue
        if result > 0:
            return result
    return 0


async def _tool_count(server: Any) -> int:
    tools = await server.list_tools()
    return len(tools)


async def main() -> int:
    try:
        task_id = int(os.environ.get("ARTEX_ACCEPTANCE_TASK_ID", "3"))
    except ValueError:
        print("FAIL invalid ARTEX_ACCEPTANCE_TASK_ID")
        return 2
    if task_id <= 0:
        print("FAIL ARTEX_ACCEPTANCE_TASK_ID must be positive")
        return 2

    servers = {
        "artex_ro": artex_ro,
        "artex_evidence_writer": evidence_writer,
        "artex_task_setup": task_setup,
        "artex_target_request": target_request,
    }
    counts: dict[str, int] = {}
    try:
        for name, server in servers.items():
            counts[name] = await _tool_count(server)
    except Exception as exc:  # Do not print server data or exception bodies.
        print(f"FAIL connector inventory ({type(exc).__name__})")
        return 1
    print("connector_tools", json.dumps(counts, sort_keys=True))
    for name, expected in EXPECTED_CONNECTOR_COUNTS.items():
        if counts.get(name) != expected:
            print(f"FAIL {name} tool count expected={expected} actual={counts.get(name)}")
            return 1

    try:
        health = await _call(artex_ro, "artex_health", {})
        if not isinstance(health, dict) or health.get("ok") is not True:
            print("FAIL artex_health")
            return 1
        print("health", {key: health.get(key) for key in ("ok", "service", "version")})

        context = await _call(artex_ro, "artex_get_task_context", {"task_id": task_id})
        if not isinstance(context, dict):
            print("FAIL task_context response shape")
            return 1
        task = context.get("task") if isinstance(context.get("task"), dict) else {}
        print("task_context", json.dumps({
            "task_id": task.get("id", task.get("task_id")),
            "name": task.get("name"),
            "status": task.get("status"),
            "goals_count": _collection_count(context.get("goals"), "goals"),
            "scope_count": _collection_count(context.get("scope"), "scope"),
            "constraint_count": _collection_count(context.get("constraints"), "constraints"),
        }, ensure_ascii=True))

        findings = await _call(artex_ro, "artex_list_task_findings", {"task_id": task_id})
        finding_rows = _rows(findings, ("findings", "items", "data", "results"))
        selected_finding_id = _finding_id(findings)
        print("findings_count", len(finding_rows))

        bundle = await _call(artex_ro, "artex_get_task_surface_bundle", {
            "task_id": task_id,
            "finding_id": selected_finding_id,
        })
        surfaces = bundle.get("surfaces") if isinstance(bundle, dict) else None
        if not isinstance(surfaces, dict):
            print("FAIL task_surface_bundle response shape")
            return 1
        names = set(surfaces)
        errors = [
            name for name, result in surfaces.items()
            if isinstance(result, dict) and result.get("error")
        ]
        print("surface_count", len(names))
        print("surface_names", sorted(names))
        print("surface_errors", sorted(errors))
        if names != EXPECTED_SURFACES:
            print("FAIL surface registry mismatch", {
                "missing": sorted(EXPECTED_SURFACES - names),
                "extra": sorted(names - EXPECTED_SURFACES),
            })
            return 1
        if errors:
            print("FAIL one or more Task surfaces returned an error")
            return 1

        dashboard = await _call(artex_ro, "artex_get_dashboard_snapshot", {"task_id": task_id})
        panels = dashboard.get("panels") if isinstance(dashboard, dict) else None
        if not isinstance(panels, dict):
            print("FAIL dashboard response shape")
            return 1
        print("dashboard", {
            "read_only": dashboard.get("read_only"),
            "task_selection": dashboard.get("task_selection"),
            "panel_count": len(panels),
            "panels": sorted(panels),
        })
        if dashboard.get("read_only") is not True or dashboard.get("task_selection") != "explicit":
            print("FAIL dashboard safety/selection metadata")
            return 1
    except Exception as exc:  # MCP errors may include sensitive task data.
        print(f"FAIL read-only MCP acceptance ({type(exc).__name__})")
        return 1

    print("PASS registered MCP handlers and local ARTEx read-only surfaces")
    print("NOTE this in-process run does not verify stdio transport or Cowork account execution")
    print("NOTE no writer, task-setup, target-request send, or browser tool was called")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
