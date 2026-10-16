"""ARTEx role inventory and capability boundaries.

This is a local orchestration manifest, not a live import from ARTEx. Keep
server/skill/tool visibility explicit here and reconcile it against the ARTEx
Agent, MCP, Skill, and Tool pages before enabling execution.
"""

from dataclasses import dataclass
from enum import StrEnum
import json
from pathlib import Path


class Trigger(StrEnum):
    TASK_SETUP = "task_setup"
    PLANNER_CYCLE = "planner_cycle"
    USER_TURN = "user_turn"
    CLAIMED_INTENT = "claimed_intent"
    USER_INVOKED = "user_invoked"
    FINDING_CREATED = "finding_created"
    RETEST_MANUAL = "retest_manual"


@dataclass(frozen=True)
class AgentRole:
    key: str
    display_name: str
    trigger: Trigger
    prompt_source: str
    prompt_file: str
    wrapup_source: str
    wrapup_file: str | None
    tool_groups: tuple[str, ...]
    mcp_servers: tuple[str, ...] = ()
    skills: tuple[str, ...] = ()
    writes_to_artex: bool = False


# Role keys match ARTEx. Tool groups are named capabilities; concrete tool
# names/bindings must be imported from the user's live ARTEx configuration.
AGENTS: dict[str, AgentRole] = {
    "goals": AgentRole(
        "goals", "目标拆解", Trigger.TASK_SETUP,
        "ARTEx agent/goals.go:goalsDefaultTmpl", "agents/goals/system.md", "generic fallback", "agents/generic-wrapup.md",
        ("goal_write", "constraint_write"), writes_to_artex=True,
    ),
    "planner": AgentRole(
        "planner", "规划", Trigger.PLANNER_CYCLE,
        "ARTEx agent/planner.go:plannerDefaultTmpl", "agents/planner/system.md", "wrapup.go planner + task-timeout defaults", "agents/planner/wrapup.md",
        ("graph_read", "goal_judgment", "intent_dispatch", "worker_steering"),
        writes_to_artex=True,
    ),
    "mainagent": AgentRole(
        "mainagent", "主", Trigger.USER_TURN,
        "ARTEx agent/mainagent.go:mainAgentDefaultTmpl", "agents/mainagent/system.md", "wrapup.go mainagent default", "agents/mainagent/wrapup.md",
        ("graph_read", "human_hint", "intent_dispatch", "scope_write"),
        writes_to_artex=True,
    ),
    "worker": AgentRole(
        "worker", "执行", Trigger.CLAIMED_INTENT,
        "ARTEx agent/worker.go:workerDefaultTmpl", "agents/worker/system.md", "worker per-run + task-timeout defaults", "agents/worker/wrapup.md",
        ("authorized_target_io", "asset_write", "fact_write", "finding_write", "traffic_read"),
        # The screenshot shows api-recon exposed to worker; verify this against
        # each skill's actual visibility and the current server configuration.
        skills=("api-recon",), writes_to_artex=True,
    ),
    "auto": AgentRole(
        "auto", "Auto", Trigger.USER_INVOKED,
        "ARTEx agent/promptcatalog.go:autoDefaultTmpl", "agents/auto/system.md", "generic fallback", "agents/generic-wrapup.md",
        ("task_admin", "asset_admin", "skill_admin", "tool_admin", "mcp_admin"),
        writes_to_artex=True,
    ),
    "pentest": AgentRole(
        "pentest", "渗透测试", Trigger.USER_INVOKED,
        "ARTEx agent/promptcatalog.go:pentestDefaultTmpl", "agents/pentest/system.md", "generic + code-owned artifact instructions", "agents/generic-wrapup.md",
        ("authorized_target_io", "asset_read_write", "finding_write", "self_planning"),
        skills=("api-recon",), writes_to_artex=True,
    ),
    "reporter": AgentRole(
        "reporter", "보고서 작성", Trigger.FINDING_CREATED,
        "ARTEx agent/promptcatalog.go:ReporterDefaultPrompt", "agents/reporter/system.md", "generic fallback", "agents/generic-wrapup.md",
        ("finding_evidence_read", "traffic_evidence_read", "report_write"),
        writes_to_artex=True,
    ),
    "retester": AgentRole(
        "retester", "漏洞复测", Trigger.RETEST_MANUAL,
        "ARTEx agent/retester.go:RetesterDefaultPrompt", "agents/retester/system.md", "generic fallback", "agents/generic-wrapup.md",
        ("original_evidence_read", "authorized_retest", "retest_result_write"),
        writes_to_artex=True,
    ),
}


# Registered MCP servers from the user's ARTEx configuration. The supplied
# screen says neither server has discovered tools yet. No agent is granted one
# by default; add explicit per-agent allow-lists after verifying live settings.
MCP_SERVERS: dict[str, dict[str, object]] = {
    "ScopeSentry": {"transport": "http", "default_enabled": False, "status": "placeholder_requires_url_and_api_key"},
    "browser": {"transport": "stdio", "command": "npx", "args": ["@playwright/mcp", "--headless"], "default_enabled": False, "status": "runtime_tool_discovery"},
}


# Source defaults and the user's screenshot agree for api-recon. The two other
# skills ship hidden by default; their live visibility may have been edited.
SKILL_INVENTORY: dict[str, dict[str, tuple[str, ...]]] = {
    "api-recon": {"visible_to": ("worker", "auto", "pentest")},
    "playwright-cli": {"visible_to": ()},
    "scopesentry": {"visible_to": ()},
}

SKILL_DEPENDENCIES = {"scopesentry": ("ScopeSentry",)}


def load_role_text(role_key: str, *, wrapup: bool = False) -> str:
    """Read an extracted ARTEx prompt; prompt templates may still need runtime variables/tools."""
    role = AGENTS[role_key]
    relative = role.wrapup_file if wrapup else role.prompt_file
    if relative is None:
        return ""
    path = Path(__file__).resolve().parents[2] / relative
    return path.read_text(encoding="utf-8")


def load_skill_text(skill_name: str) -> str:
    """Load the bundled skill instructions. This does not grant its MCP/tool access."""
    if skill_name not in SKILL_INVENTORY:
        raise KeyError(f"Unknown skill: {skill_name}")
    path = Path(__file__).resolve().parents[2] / "skills" / skill_name / "SKILL.md"
    return path.read_text(encoding="utf-8")


def validate_manifest() -> None:
    expected = {"goals", "planner", "mainagent", "worker", "auto", "pentest", "reporter", "retester"}
    if set(AGENTS) != expected:
        raise ValueError(f"Agent inventory mismatch: {set(AGENTS) ^ expected}")
    for role in AGENTS.values():
        unknown = set(role.skills) - set(SKILL_INVENTORY)
        if unknown:
            raise ValueError(f"{role.key} references unknown skills: {sorted(unknown)}")
        for skill in role.skills:
            if role.key not in SKILL_INVENTORY[skill]["visible_to"]:
                raise ValueError(f"{role.key} cannot see skill {skill} per current manifest")


validate_manifest()


def load_tool_bindings(path: Path | None = None) -> dict[str, tuple[str, ...]]:
    """Load the captured ARTEx tool→agent binding list; it does not execute tools."""
    source = path or Path(__file__).resolve().parents[2] / "config" / "artex-tool-bindings.json"
    data = json.loads(source.read_text(encoding="utf-8"))
    result = {key: [] for key in AGENTS}
    for item in data.get("tools", []):
        for agent_key in item.get("agents", []):
            if agent_key not in result:
                raise ValueError(f"Tool {item.get('name')} references unknown agent {agent_key}")
            result[agent_key].append(item["name"])
    return {key: tuple(names) for key, names in result.items()}


TOOL_BINDINGS = load_tool_bindings()
