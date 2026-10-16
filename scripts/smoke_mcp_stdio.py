"""Initialize each local ARTEx MCP connector and list tools over MCP stdio.

This is a transport smoke check only. It does not call any ARTEx tool, write
data, or send a target request. It uses the official MCP Python client so the
check follows the same stdio framing/negotiation used by MCP clients.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable)
SERVERS = {
    "artex_ro": ("artex_agent.desktop_mcp", 17),
    "artex_evidence_writer": ("artex_agent.desktop_diagnostic_writer", 14),
    "artex_task_setup": ("artex_agent.desktop_task_setup_mcp", 5),
    "artex_target_request": ("artex_agent.desktop_target_mcp", 4),
}
HANDSHAKE_TIMEOUT_SECONDS = 30


async def check_server(name: str, module: str, expected_count: int) -> None:
    env = dict(os.environ)
    env["ARTEX_API_BASE_URL"] = "http://127.0.0.1:8787"
    params = StdioServerParameters(
        command=str(PYTHON), args=["-m", module], env=env, cwd=ROOT,
    )
    async with asyncio.timeout(HANDSHAKE_TIMEOUT_SECONDS):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                names = [tool.name for tool in result.tools]
                if len(names) != expected_count or any(not item for item in names):
                    raise RuntimeError(
                        f"{name}: expected {expected_count} named tools, received {len(names)}"
                    )
                print(f"{name}: initialized; {len(names)} tools", flush=True)


async def main() -> int:
    if not PYTHON.is_file():
        raise FileNotFoundError(f"Plugin Python environment not found: {PYTHON}")
    for name, (module, expected_count) in SERVERS.items():
        print(f"{name}: starting MCP stdio handshake", flush=True)
        await check_server(name, module, expected_count)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except Exception as exc:
        print(f"MCP stdio smoke check failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)

