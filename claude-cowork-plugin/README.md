# ARTEx Agent Profiles for Claude Desktop

This plugin provides ARTEx role profiles, reusable skills, assessment commands, and local MCP connector definitions. The connectors access an ARTEx instance explicitly configured by the operator. No credentials or task-specific evidence are included. The read-only/evidence fixture connectors retain their explicit local-only target guard, while the target-request connector relies on the ARTEx task scope and human allow/deny checks.

## Components

- `agents/`: coordinator, planner, pentest, worker, reporter, retester, and goal/task roles.
- `skills/`: ARTEx workflow, API reconnaissance, browser workflow, scope handling, and web assessment references.
- `commands/`: reusable assessment workflows.
- `references/role-tool-mapping.json`: source role/tool inventory and documented capability limits.
- `.mcp.json.example`: portable local connector configuration; replace the path placeholders before use.

The target-request connector is bounded by task authorization, approved origin, method set, request budget, rate, and stop conditions. It is not a broad scanner. Finding registration requires evidence and the writer's operation-specific confirmation. Local connector configuration does not grant access to an ARTEx account or change an ARTEx task by itself.

## Runtime boundary

Agent profiles execute in the Claude Desktop session that invokes them. ARTEx's native planner/worker service has its own runtime and LLM configuration; this plugin does not transfer Claude session credentials to that service. The supported integration path is Claude Desktop invoking local ARTEx MCP connectors.

## Installation notes

Install the Python project from the repository root, configure the four local MCP servers using the example file and your local paths, then install the plugin package in Claude Desktop. Keep local paths, credentials, API keys, session values, runtime data, and task-specific assessment records out of source control.

