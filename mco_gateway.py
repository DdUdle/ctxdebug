#!/usr/bin/env python3
"""
MCO Gateway — Unified MCP proxy that fans out to all MCO sub-servers over one stdio connection.

Usage:
    python mco_gateway.py                        # start all servers
    MCO_SERVERS=sessions python mco_gateway.py   # start only sessions sub-server
    MCO_STARTUP_TIMEOUT=15 python mco_gateway.py # longer startup grace period

Registration (one command replaces five):
    claude mcp add mco-gateway -- python "C:\\path\\mco\\mco_gateway.py"

Environment:
    MCO_SERVERS          — comma-separated subset of server names to enable
                           (omit to enable all; e.g. "sessions,windbg")
    MCO_STARTUP_TIMEOUT  — seconds to wait for each sub-server to initialize (default: 10)
"""

import json
import os
import secrets
import subprocess
import sys
import threading
import time
import logging
import atexit
from collections import deque
from queue import Empty, Queue

log = logging.getLogger("mco.gateway")
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="[MCO] %(levelname)s %(message)s"
)

MCO_ROOT = os.path.dirname(os.path.abspath(__file__))


def _ensure_x64dbg_pipe_token(env=None) -> str:
    """Give all gateway child processes one high-entropy pipe capability."""
    target = os.environ if env is None else env
    token = (target.get("X64DBG_PIPE_TOKEN") or "").strip()
    if not token:
        token = secrets.token_hex(32)
        target["X64DBG_PIPE_TOKEN"] = token
    return token


SERVERS = [
    {
        "name": "windbg",
        "cmd": [sys.executable, os.path.join(MCO_ROOT, "windbg_mcp.py")],
        "optional": True,
        "description": "WinDbg — crash dumps, heap, shadow stack. 70+ tools."
    },
    {
        "name": "ida",
        "cmd": [sys.executable, os.path.join(MCO_ROOT, "ida_mcp.py")],
        "optional": True,
        "description": "IDA Pro 9.x — decompile, xrefs, type recovery. 32+ tools."
    },
    {
        "name": "x64dbg",
        "cmd": [sys.executable, "-m", "agent", "--mcp"],
        "cwd": MCO_ROOT,
        "optional": True,
        "description": "x64dbg — dynamic analysis, named pipe IPC. 35+ tools."
    },
    {
        "name": "orchestrator",
        "cmd": [sys.executable, os.path.join(MCO_ROOT, "mco_orchestrator.py")],
        "optional": True,
        "description": "Cross-debugger workflows — 7 meta-tools."
    },
    {
        "name": "sessions",
        "cmd": [sys.executable, os.path.join(MCO_ROOT, "mco_sessions.py")],
        "optional": False,
        "description": "Session recorder — 13 tools."
    },
]


# ─────────────────────────────────────────────────────────────
#  SubServer — manages one child MCP process
# ─────────────────────────────────────────────────────────────

class SubServer:
    def __init__(self, config: dict):
        self.name = config["name"]
        self.cmd = config["cmd"]
        self.cwd = config.get("cwd", MCO_ROOT)
        self.optional = config.get("optional", True)
        self.description = config.get("description", "")
        self.tools: list[dict] = []
        self.proc: subprocess.Popen | None = None
        self._id = 0
        self._lock = threading.Lock()
        self.started_at: float | None = None
        self.failed = False
        self._stdout_q: Queue[str | None] = Queue()
        self._stderr_tail = deque(maxlen=50)
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None

    def start(self, timeout: float = 10.0) -> bool:
        env = {**os.environ}
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=self.cwd,
                env=env
            )
            self.started_at = time.time()
            self.failed = False
            self._stdout_q = Queue()
            self._stderr_tail = deque(maxlen=50)
            self._start_readers()

            # MCP handshake: initialize
            init_resp = self._rpc("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mco-gateway", "version": "1.0.0"}
            }, timeout=timeout)
            if "error" in init_resp:
                raise RuntimeError(f"initialize failed: {init_resp['error']}")

            # Acknowledge
            self._send_notify("notifications/initialized", {})

            # Fetch tool list
            tools_resp = self._rpc("tools/list", {}, timeout=timeout)
            self.tools = tools_resp.get("result", {}).get("tools", [])
            log.info(f"{self.name}: started, {len(self.tools)} tools")
            return True

        except Exception as e:
            tail = " | ".join(self._stderr_tail)
            suffix = f" | stderr: {tail}" if tail else ""
            log.warning(f"{self.name}: failed to start — {e}{suffix}")
            self.failed = True
            if self.proc:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=1)
                except Exception:
                    self.proc.kill()
                self.proc = None
            self.tools = []
            return False

    def _start_readers(self) -> None:
        assert self.proc and self.proc.stdout and self.proc.stderr
        stdout = self.proc.stdout
        stderr = self.proc.stderr
        stdout_q = self._stdout_q
        stderr_tail = self._stderr_tail
        server_name = self.name

        def _stdout_reader():
            try:
                for line in stdout:
                    stdout_q.put(line)
            finally:
                stdout_q.put(None)

        def _stderr_reader():
            for line in stderr:
                text = line.rstrip()
                if text:
                    stderr_tail.append(text)
                    log.debug("%s stderr: %s", server_name, text)

        self._stdout_thread = threading.Thread(
            target=_stdout_reader,
            daemon=True,
            name=f"mco-{self.name}-stdout",
        )
        self._stderr_thread = threading.Thread(
            target=_stderr_reader,
            daemon=True,
            name=f"mco-{self.name}-stderr",
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send_notify(self, method: str, params: dict):
        msg = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n"
        self.proc.stdin.write(msg)
        self.proc.stdin.flush()

    def _rpc(self, method: str, params: dict, timeout: float = 30.0) -> dict:
        if not self.proc or self.proc.poll() is not None or not self.proc.stdin:
            raise RuntimeError(f"{self.name} server is not running")

        req_id = self._next_id()
        msg = json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params
        }) + "\n"
        self.proc.stdin.write(msg)
        self.proc.stdin.flush()

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                tail = "\n".join(self._stderr_tail)
                detail = f"; stderr tail: {tail}" if tail else ""
                raise TimeoutError(
                    f"{self.name} RPC timeout ({method}) after {timeout:.1f}s{detail}"
                )
            try:
                line = self._stdout_q.get(timeout=remaining)
            except Empty:
                continue

            if line is None:
                tail = "\n".join(self._stderr_tail)
                detail = f": {tail}" if tail else ""
                raise RuntimeError(f"{self.name} stdout closed{detail}")

            try:
                resp = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
            if resp.get("id") == req_id:
                return resp

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        if not self.proc or self.proc.poll() is not None:
            return {
                "content": [{"type": "text", "text": f"ERROR: {self.name} server is not running"}],
                "isError": True
            }
        with self._lock:
            try:
                resp = self._rpc(
                    "tools/call",
                    {"name": tool_name, "arguments": arguments},
                    timeout=120.0
                )
                return resp.get("result", {
                    "content": [{"type": "text", "text": "No result"}],
                    "isError": False
                })
            except Exception as e:
                return {
                    "content": [{"type": "text", "text": f"ERROR: {e}"}],
                    "isError": True
                }

    def stop(self):
        if self.proc:
            try:
                self.proc.stdin.write(
                    json.dumps({
                        "jsonrpc": "2.0",
                        "method": "notifications/cancelled",
                        "params": {}
                    }) + "\n"
                )
                self.proc.stdin.flush()
            except Exception:
                pass
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()
            self.proc = None
        self.tools = []

    @property
    def uptime(self) -> str | None:
        if not self.started_at:
            return None
        s = int(time.time() - self.started_at)
        return f"{s // 60}m {s % 60}s" if s >= 60 else f"{s}s"

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


# ─────────────────────────────────────────────────────────────
#  Gateway — manages all SubServers and the tool routing table
# ─────────────────────────────────────────────────────────────

class Gateway:
    def __init__(self):
        self.x64dbg_pipe_token = _ensure_x64dbg_pipe_token()
        enabled = (
            set(os.environ["MCO_SERVERS"].split(","))
            if os.environ.get("MCO_SERVERS")
            else None
        )
        timeout = float(os.environ.get("MCO_STARTUP_TIMEOUT", "10"))

        self.servers: list[SubServer] = []
        self.tool_map: dict[str, SubServer] = {}   # tool_name → SubServer

        for cfg in SERVERS:
            if enabled and cfg["name"] not in enabled:
                continue
            srv = SubServer(cfg)
            ok = srv.start(timeout=timeout)
            if not ok and not cfg.get("optional", True):
                log.error(f"Required server {cfg['name']} failed — gateway degraded")
            # Always track in server list for status/restart commands
            self.servers.append(srv)

        self._rebuild_tool_map()
        atexit.register(self._shutdown)
        total = sum(len(s.tools) for s in self.servers if s.running)
        log.info(
            f"Gateway ready: {sum(s.running for s in self.servers)}/{len(self.servers)} "
            f"servers, {total} tools"
        )

    def _shutdown(self):
        for srv in self.servers:
            srv.stop()

    def _rebuild_tool_map(self) -> None:
        """Rebuild routing from the currently running servers only."""
        tool_map: dict[str, SubServer] = {}
        for srv in self.servers:
            if not srv.running:
                continue
            for tool in srv.tools:
                tool_map.setdefault(tool["name"], srv)
        self.tool_map = tool_map

    # ── Gateway's own built-in tools ─────────────────────────

    _GATEWAY_TOOLS = [
        {
            "name": "mco_gateway_status",
            "description": "Show status of all MCO sub-servers: running/stopped, PID, tool count, uptime.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        },
        {
            "name": "mco_restart_server",
            "description": (
                "Restart a crashed MCO sub-server by name "
                "(windbg / ida / x64dbg / orchestrator / sessions)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server_name": {"type": "string", "description": "Name of the sub-server to restart"}
                },
                "required": ["server_name"]
            }
        },
        {
            "name": "mco_list_servers",
            "description": "List all configured MCO sub-servers with description and tool counts.",
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }
    ]

    def get_all_tools(self) -> list[dict]:
        all_proxied: list[dict] = []
        for srv in self.servers:
            if srv.running:
                all_proxied.extend(srv.tools)
        return self._GATEWAY_TOOLS + all_proxied

    def handle_tool(self, tool_name: str, arguments: dict) -> dict:
        # ── Gateway built-ins ────────────────────────────────

        if tool_name == "mco_gateway_status":
            data = {
                "servers": [
                    {
                        "name": s.name,
                        "running": s.running,
                        "failed": s.failed,
                        "pid": s.proc.pid if s.proc else None,
                        "tool_count": len(s.tools),
                        "uptime": s.uptime,
                        "description": s.description
                    }
                    for s in self.servers
                ],
                "total_tools": len(self.tool_map),
                "active_servers": sum(s.running for s in self.servers)
            }
            return {
                "content": [{"type": "text", "text": json.dumps(data, indent=2)}],
                "isError": False
            }

        if tool_name == "mco_list_servers":
            data = [
                {
                    "name": s.name,
                    "running": s.running,
                    "tools": len(s.tools),
                    "description": s.description
                }
                for s in self.servers
            ]
            return {
                "content": [{"type": "text", "text": json.dumps(data, indent=2)}],
                "isError": False
            }

        if tool_name == "mco_restart_server":
            name = arguments.get("server_name", "")
            for s in self.servers:
                if s.name == name:
                    s.stop()
                    s.failed = False
                    ok = s.start(timeout=15)
                    self._rebuild_tool_map()
                    msg = f"{name}: {'restarted OK' if ok else 'failed to restart'}"
                    return {
                        "content": [{"type": "text", "text": msg}],
                        "isError": not ok
                    }
            return {
                "content": [{"type": "text", "text": f"Server '{name}' not found"}],
                "isError": True
            }

        # ── Proxy to sub-server ──────────────────────────────
        srv = self.tool_map.get(tool_name)
        if not srv:
            return {
                "content": [{"type": "text", "text": f"ERROR: Unknown tool '{tool_name}'"}],
                "isError": True
            }
        return srv.call_tool(tool_name, arguments)


# ─────────────────────────────────────────────────────────────
#  Main MCP stdio loop
# ─────────────────────────────────────────────────────────────

def main():
    gateway = Gateway()
    all_tools = gateway.get_all_tools()

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")
        params = req.get("params", {})

        if method == "initialize":
            all_tools = gateway.get_all_tools()
            total_tools = len(all_tools)
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "mco-gateway",
                        "version": "1.0.0",
                        "description": (
                            f"MCO Unified Gateway — {total_tools} tools "
                            f"across {len(gateway.servers)} debuggers"
                        )
                    }
                }
            }), flush=True)

        elif method == "notifications/initialized":
            pass  # no response needed

        elif method == "tools/list":
            # Refresh tool list (servers may have restarted)
            all_tools = gateway.get_all_tools()
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": all_tools}
            }), flush=True)

        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            result = gateway.handle_tool(tool_name, arguments)
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }), flush=True)

        elif req_id is not None:
            # Unknown method with an id — return proper JSON-RPC error
            print(json.dumps({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }), flush=True)
        # Notifications with no id: silently ignore


if __name__ == "__main__":
    main()
