# Cowork plugin read-only acceptance prompt

Use this prompt to check a locally installed ARTEx Agent Profiles plugin through a Cowork task started in Claude Desktop. Keep Desktop open so it can broker local MCP connections. Replace `<task_id>` with an existing, non-sensitive test Task that is safe to inspect. This prompt performs reads only; it does not modify Task data or contact a diagnostic target.

```text
Run a read-only acceptance check of the installed ARTEx Agent Profiles plugin against the operator's local ARTEx instance.

Use the operator-selected existing test Task (task_id=<task_id>). Call only these read-only plugin MCP tools:
1. artex_health
2. artex_get_task_context(task_id=<task_id>)
3. artex_list_task_findings(task_id=<task_id>)
4. artex_get_task_surface_bundle(task_id=<task_id>, finding_id=<first returned finding ID; omit if there are no findings>)
5. artex_get_dashboard_snapshot(task_id=<task_id>)

Do not call any evidence writer, task setup, intercept decision, target-request, browser, shell, or other write/action tool. Do not contact any diagnostic target. Do not alter task data.

Report:
- whether all four local MCP connectors started and their visible tool counts;
- each call's success/error and the returned ARTEx version;
- whether the bundle contains the currently supported Task surfaces; list the returned surface names;
- whether the dashboard snapshot is read-only and which panels it includes;
- any authentication, local-bridge, or permission error.

If a required tool is missing or the Desktop broker cannot start a local MCP connector, stop and report that limitation. Do not switch runtimes, use an API key, expose a public MCP endpoint, or substitute another connector.
```

Tool names, surface lists, and counts can change between releases. Report the values returned by the installed version; do not treat historical counts as requirements.
