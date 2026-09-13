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


def read_stdio_message() -> tuple[str | None, bool]:
    """Read one JSON-RPC message from stdin.

    Supports MCP newline-delimited JSON and LSP-style ``Content-Length``
    framing. Returns ``(text, used_content_length)``. ``text is None`` means EOF.
    """
    buf = getattr(sys.stdin, "buffer", None)
    if buf is None:
        line = sys.stdin.readline()
        if line == "":
            return None, False
        return line.strip(), False

    header = buf.readline()
    if not header:
        return None, False
    if header.lower().startswith(b"content-length:"):
        try:
            length = int(header.split(b":", 1)[1].strip())
        except ValueError:
            return "", False
        while True:
            line = buf.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        body = buf.read(length) if length else b""
        return body.decode("utf-8", errors="replace"), True
    return header.decode("utf-8", errors="replace").strip(), False


def write_stdio_message(obj: dict, content_length: bool = False) -> None:
    """Write one JSON-RPC message to stdout using the same framing as the client."""
    data = json.dumps(obj, ensure_ascii=False)
    outbuf = getattr(sys.stdout, "buffer", None)
    if content_length and outbuf is not None:
        raw = data.encode("utf-8")
        outbuf.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii"))
        outbuf.write(raw)
        outbuf.flush()
        return
    sys.stdout.write(data + "\n")
    sys.stdout.flush()


def serve_stdio(handle: Callable[[dict], dict | None]) -> None:
    """Run the stdin JSON-RPC read loop, dispatching each request to ``handle``.

    Blank lines and undecodable JSON are skipped; a non-``None`` handler return
    value is serialised and written to stdout followed by a flush.
    """
    while True:
        raw, content_length = read_stdio_message()
        if raw is None:
            break
        raw = raw.strip()
        if not raw:
            continue
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            continue
        response = handle(request)
        if response is not None:
            write_stdio_message(response, content_length=content_length)
