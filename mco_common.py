"""Shared helpers for the stdio JSON-RPC MCP servers.

These utilities were duplicated verbatim across the standalone MCP server
scripts (``windbg_mcp``, ``ida_mcp``, ``mco_orchestrator``, ``mco_sessions``).
They are centralised here so the servers share a single implementation.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable


def section(title: str, body: str) -> str:
    """Render a titled ``### `` markdown section, showing ``(empty)`` if blank."""
    body = (body or "").strip("\n")
    if not body:
        body = "(empty)"
    return f"### {title}\n{body}"


def kv_block(pairs: list[tuple[str, Any]]) -> str:
    """Render ``key = value`` pairs with the keys left-padded to equal width."""
    if not pairs:
        return "(none)"
    width = max(len(k) for k, _ in pairs)
    return "\n".join(f"{k.ljust(width)} = {v}" for k, v in pairs)


def text_result(data: Any) -> dict:
    """Wrap ``data`` in an MCP ``tools/call`` text content result."""
    text = data if isinstance(data, str) else json.dumps(data, indent=2)
    return {"content": [{"type": "text", "text": text}], "isError": False}


def text_error(msg: str) -> dict:
    """Wrap an error message in an MCP ``tools/call`` text content result."""
    return {"content": [{"type": "text", "text": f"ERROR: {msg}"}], "isError": True}


def serve_stdio(handle: Callable[[dict], dict | None]) -> None:
    """Run the stdin JSON-RPC read loop, dispatching each request to ``handle``.

    Blank lines and undecodable JSON are skipped; a non-``None`` handler return
    value is serialised and written to stdout followed by a flush.
    """
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle(request)
        if response is not None:
            print(json.dumps(response), flush=True)
