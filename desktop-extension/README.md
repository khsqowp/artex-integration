# ARTEx Claude Desktop Extension

The `.mcpb` package installs the local ARTEx MCP connector in Claude Desktop. It does not install or start ARTEx itself. Install and run ARTEx separately, then configure its local URL and an ARTEx account in the extension settings. Only `127.0.0.1` or `localhost` on port `8787` is accepted.

The extension provides one MCP server containing the read, evidence/report, task-setup, and bounded target-request tools. Target requests remain subject to ARTEx task scope, allow/deny constraints, and run budget.

Build from the Claude integration repository with `python scripts/package_desktop_extension.py`. The package uses the MCPB `uv` runtime and declares dependencies in `pyproject.toml`.
