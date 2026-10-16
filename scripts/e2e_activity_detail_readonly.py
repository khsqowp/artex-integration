"""Read one existing Cowork activity detail without printing its contents."""

from __future__ import annotations

import argparse
import json

from artex_agent.desktop_mcp import artex_get_task_activity_detail, artex_get_task_surface


def _decode(value: str) -> dict:
    parsed = json.loads(value)
    if isinstance(parsed, dict) and set(parsed) == {"result"}:
        parsed = json.loads(parsed["result"])
    if not isinstance(parsed, dict):
        raise ValueError("unexpected activity response")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", type=int, required=True)
    parser.add_argument("--tool-use-id", required=True)
    args = parser.parse_args()
    history = _decode(artex_get_task_surface(
        args.task_id, "session_history", session="cowork", size=500,
    ))
    rows = history.get("items", [])
    match = next((
        row for row in rows
        if isinstance(row, dict)
        and row.get("tool") == "complete_intent"
        and row.get("tool_use_id") == args.tool_use_id
    ), None)
    if not match:
        print(json.dumps({"matched": False, "history_rows": len(rows)}))
        return 2
    seq = int(match.get("seq") or 0)
    if seq <= 0:
        print(json.dumps({"matched": True, "seq_valid": False}))
        return 1
    detail = _decode(artex_get_task_activity_detail(args.task_id, seq))
    body = detail.get("detail", "")
    if not isinstance(body, str):
        print(json.dumps({"matched": True, "seq": seq, "detail_type": type(body).__name__}))
        return 1
    result = {
        "matched": True,
        "task_id": args.task_id,
        "seq": seq,
        "detail_present": bool(body),
        "synthetic_marker_present": "SYNTHETIC COWORK ACCEPTANCE TEST" in body,
        "detail_chars": len(body),
    }
    print(json.dumps(result))
    return 0 if result["detail_present"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
