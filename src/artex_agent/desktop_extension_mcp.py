"""Single-server entry point for the installable Claude Desktop extension."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import desktop_diagnostic_writer, desktop_mcp, desktop_target_mcp, desktop_task_setup_mcp


server = FastMCP("artex")

# Keep the connector-specific modules as the source of truth while publishing
# their disjoint tools through one installable Desktop Extension.
for connector in (
    desktop_mcp.server,
    desktop_diagnostic_writer.server,
    desktop_task_setup_mcp.server,
    desktop_target_mcp.server,
):
    for tool in connector._tool_manager.list_tools():
        server.add_tool(tool.fn, name=tool.name, description=tool.description)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
