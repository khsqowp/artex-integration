"""Read-only end-to-end check of the packaged ARTEx Cowork MCP connector.

Calls only health, task-scoped read tools, and the dashboard snapshot. It uses
an existing finding ID to exercise the native retest-history read. No writer
or diagnostic target is contacted. Output is reduced to surface names/counts.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from artex_agent.auth_store import SERVICE, USERNAME
from artex_agent.artex_api import TASK_DETAIL_SURFACES
import keyring


ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
TASK_ID = int(os.environ.get("ARTEX_ACCEPTANCE_TASK_ID", "3"))


def parse_text(result) -> dict:
    for item in result.content:
        if getattr(item, "type", None) == "text":
            return json.loads(item.text)
    raise RuntimeError("MCP tool returned no JSON text result")


def shape(value) -> str:
    if isinstance(value, list):
        return f"list_count={len(value)}"
    if isinstance(value, dict):
        if isinstance(value.get("rules"), list):
            return f"rules_count={len(value['rules'])}"
        for key in ("items", "nodes", "findings", "retests", "assets", "records", "sessions", "events", "results"):
            if isinstance(value.get(key), list):
                return f"{key}_count={len(value[key])}"
        return "object_fields=" + ",".join(sorted(value.keys()))
    return f"value_type={type(value).__name__}"


async def main() -> None:
    password = keyring.get_password(SERVICE, USERNAME)
    if not password:
        raise RuntimeError("ARTEx credential is not present in Windows Credential Manager")
    env = dict(os.environ)
    env["ARTEX_API_BASE_URL"] = "http://127.0.0.1:8787"
    params = StdioServerParameters(
        command=str(PYTHON), args=["-m", "artex_agent.desktop_mcp"], env=env, cwd=ROOT,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=20)
            tools = await asyncio.wait_for(session.list_tools(), timeout=20)
            names = {tool.name for tool in tools.tools}
            required = {
                "artex_health", "artex_get_task_surface",
                "artex_get_task_surface_bundle", "artex_get_dashboard_snapshot",
            }
            missing = required - names
            if missing:
                raise RuntimeError(f"Missing read-only MCP tools: {sorted(missing)}")
            health = parse_text(await asyncio.wait_for(session.call_tool("artex_health", {}), timeout=20))
            if not health.get("ok"):
                raise RuntimeError("ARTEx health did not return ok=true")
            findings = parse_text(await asyncio.wait_for(
                session.call_tool("artex_get_task_surface", {
                    "task_id": TASK_ID, "surface": "findings",
                }), timeout=30,
            ))
            if not isinstance(findings, list):
                raise RuntimeError("Task findings surface did not return a list")
            finding_id = 0
            for finding in findings:
                if isinstance(finding, dict):
                    try:
                        finding_id = int(finding.get("finding_id") or finding.get("id") or 0)
                    except (TypeError, ValueError):
                        finding_id = 0
                    if finding_id > 0:
                        break
            bundle = parse_text(await asyncio.wait_for(
                session.call_tool("artex_get_task_surface_bundle", {
                    "task_id": TASK_ID, "finding_id": finding_id,
                }), timeout=90,
            ))
            if bundle.get("task_id") != TASK_ID or bundle.get("read_only") is not True:
                raise RuntimeError("Task surface bundle did not confirm the requested task and read-only mode")
            surfaces = bundle.get("surfaces")
            if not isinstance(surfaces, dict):
                raise RuntimeError("Task surface bundle has no surfaces object")
            required_surfaces = set(TASK_DETAIL_SURFACES) | {"cowork_activity", "retests"}
            missing_surfaces = required_surfaces - set(surfaces)
            if missing_surfaces:
                raise RuntimeError(f"Task surface bundle is missing surfaces: {sorted(missing_surfaces)}")
            retests = surfaces["retests"]
            if finding_id > 0:
                if isinstance(retests, dict) and (retests.get("read_error") or retests.get("skipped")):
                    raise RuntimeError("Finding-backed retest history was not read successfully")
            elif not (isinstance(retests, dict) and retests.get("skipped")):
                raise RuntimeError("Retest history should be skipped when the task has no findings")
            intercept_rules = parse_text(await asyncio.wait_for(
                session.call_tool("artex_get_task_surface", {
                    "task_id": TASK_ID, "surface": "intercept_rules",
                }), timeout=30,
            ))
            if not isinstance(intercept_rules, dict) or not isinstance(intercept_rules.get("rules"), list):
                raise RuntimeError("Task intercept rules did not return a task-scoped rules list")
            dashboard = parse_text(await asyncio.wait_for(
                session.call_tool("artex_get_dashboard_snapshot", {"task_id": TASK_ID}), timeout=45,
            ))
            if dashboard.get("task_id") != TASK_ID or dashboard.get("read_only") is not True:
                raise RuntimeError("Dashboard snapshot did not confirm the requested task and read-only mode")
            panels = dashboard.get("panels")
            if not isinstance(panels, dict):
                raise RuntimeError("Dashboard snapshot has no panels object")
            print(
                f"MCP tools: {len(names)}; health: ok; task_id: {TASK_ID}; "
                f"findings: {len(findings)}; retest_history: {'read' if finding_id else 'not_applicable'}; "
                f"dashboard_panels: {len(panels)}; intercept_rules: {len(intercept_rules['rules'])}"
            )
            for name, value in surfaces.items():
                if isinstance(value, dict) and value.get("read_error"):
                    print(f"{name}: unavailable ({value['read_error']})")
                elif isinstance(value, dict) and value.get("skipped"):
                    print(f"{name}: skipped ({value['skipped']})")
                else:
                    print(f"{name}: ok; {shape(value)}")


if __name__ == "__main__":
    asyncio.run(main())
