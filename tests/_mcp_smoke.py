"""Manual MCP stdio handshake helper (also importable)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def handshake(cmd: list[str], cwd: Path | None = None) -> dict:
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd or ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
    ]
    payload = "".join(json.dumps(r) + "\n" for r in reqs)
    try:
        out, err = proc.communicate(payload, timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        raise RuntimeError(f"timeout stdout={out!r} stderr={err!r}") from None
    lines = [ln for ln in (out or "").splitlines() if ln.strip()]
    msgs = []
    for ln in lines:
        try:
            msgs.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    by_id = {m.get("id"): m for m in msgs if isinstance(m, dict) and "id" in m}
    init = by_id.get(1, {})
    tools = by_id.get(2, {})
    ping = by_id.get(3, {})
    tool_list = tools.get("result", {}).get("tools", [])
    return {
        "returncode": proc.returncode,
        "stderr": (err or "")[-2000:],
        "init_ok": "result" in init,
        "server": init.get("result", {}).get("serverInfo", {}),
        "tool_count": len(tool_list),
        "tool_names": [t.get("name") for t in tool_list[:12]],
        "ping_ok": ping.get("id") == 3 and "error" not in ping,
        "raw_lines": len(lines),
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "ida"
    if target == "ida":
        print(json.dumps(handshake([sys.executable, "ida_mcp.py"]), indent=2))
    elif target == "x64dbg":
        print(json.dumps(handshake([sys.executable, "-m", "agent", "--mcp"]), indent=2))
    else:
        raise SystemExit("usage: _mcp_smoke.py [ida|x64dbg]")
