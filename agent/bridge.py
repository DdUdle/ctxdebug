"""
x64dbg Bridge — Robust connection to x64dbg debugger.

Key improvements over existing MCP bridges:
1. Named Pipes (primary) — native Windows IPC, no port conflicts
2. HTTP fallback — compatibility with existing plugins
3. Auto-reconnection with exponential backoff
4. Connection health monitoring
5. Event streaming via overlapped I/O (pipes) or SSE (HTTP)
6. Command queuing during disconnects
"""

import asyncio
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Optional

from .x64_protocol import (
    MAX_PAYLOAD_BYTES,
    PIPE_MAGIC,
    PIPE_VERSION,
    MsgType,
    PipeHeader,
    PipeMessage,
)


def _default_socket_path() -> str:
    """Per-user path for the dev/test Unix socket."""
    runtime_dir = os.environ.get('XDG_RUNTIME_DIR')
    base = runtime_dir if runtime_dir and os.path.isdir(runtime_dir) else os.path.expanduser('~/.x64ai')
    os.makedirs(base, mode=0o700, exist_ok=True)
    return os.path.join(base, 'x64dbg_ai_agent.sock')


class ConnectionState(IntEnum):
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    RECONNECTING = 3
    ERROR = 4


class BridgeProtocol(IntEnum):
    NAMED_PIPE = 0
    HTTP = 1
    SHARED_MEMORY = 2  # Future: fastest for local


# ------------------------------------------------------------------
# Bridge — main connection manager
# ------------------------------------------------------------------
@dataclass
class PendingCommand:
    """Command waiting for response."""
    seq_id: int
    command: str
    args: dict
    future: asyncio.Future
    timestamp: float = field(default_factory=time.time)
    timeout: float = 10.0


class X64DbgBridge:
    """
    Manages connection to x64dbg and provides async command interface.

    Usage:
        bridge = X64DbgBridge()
        await bridge.connect()
        regs = await bridge.get_registers()
        await bridge.set_breakpoint(0x401000)
    """

    PIPE_NAME = r'\\.\pipe\x64dbg_ai_agent'
    HTTP_URL = 'http://127.0.0.1:27042'
    RECONNECT_DELAYS = [1, 2, 4, 8, 15, 30]  # seconds

    # Default x64dbg path — override via X64DBG_PATH env var or constructor
    X64DBG_PATH = os.environ.get('X64DBG_PATH', '')

    def __init__(self, pipe_name: str = None, http_url: str = None,
                 protocol: BridgeProtocol = BridgeProtocol.NAMED_PIPE,
                 x64dbg_path: str = None, auth_token: str = None):
        self.pipe_name = pipe_name or self.PIPE_NAME
        self.http_url = http_url or self.HTTP_URL
        self.protocol = protocol
        self._prefer_http = protocol == BridgeProtocol.HTTP
        self.x64dbg_path = x64dbg_path or self.X64DBG_PATH
        self.auth_token = auth_token if auth_token is not None else os.environ.get("X64DBG_PIPE_TOKEN", "")
        self._x64dbg_proc = None  # launched subprocess handle
        self.state = ConnectionState.DISCONNECTED
        self._seq_counter = 0
        self._pending: dict[int, PendingCommand] = {}
        self._event_handlers: dict[str, list[Callable]] = {}
        self._pipe_reader = None
        self._pipe_writer = None
        self._http_session = None
        self._heartbeat_task = None
        self._read_task = None
        self._command_queue: list[PendingCommand] = []
        self._reconnect_lock = asyncio.Lock()
        self._reconnect_task = None

    @property
    def connected(self) -> bool:
        return self.state == ConnectionState.CONNECTED

    def _next_seq(self) -> int:
        self._seq_counter += 1
        return self._seq_counter

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    async def connect(self) -> bool:
        """Connect to x64dbg.

        Named-pipe mode is authenticated and does not silently downgrade to the
        legacy HTTP transport. HTTP is used only when explicitly requested.
        """
        if self._prefer_http:
            if await self._connect_http():
                self.protocol = BridgeProtocol.HTTP
                return True
            return False

        if not self.auth_token:
            self.state = ConnectionState.DISCONNECTED
            return False

        if await self._connect_pipe():
            self.protocol = BridgeProtocol.NAMED_PIPE
            return True
        return False

    async def _connect_pipe(self) -> bool:
        """Connect via Windows Named Pipe (or Unix socket for dev/testing)."""
        self.state = ConnectionState.CONNECTING
        try:
            import sys
            if sys.platform == 'win32':
                loop = asyncio.get_running_loop()
                if not hasattr(loop, 'create_pipe_connection'):
                    self.state = ConnectionState.DISCONNECTED
                    return False
                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await asyncio.wait_for(
                    loop.create_pipe_connection(lambda: protocol, self.pipe_name),
                    timeout=3.0,
                )
                writer = asyncio.StreamWriter(transport, protocol, reader, loop)
                self._pipe_reader = reader
                self._pipe_writer = writer
            else:
                # Unix socket fallback for development/testing. Keep the socket
                # out of the world-writable temp dir so it cannot be squatted.
                sock_path = self.pipe_name if self.pipe_name.startswith('/') else _default_socket_path()
                try:
                    reader, writer = await asyncio.open_unix_connection(sock_path)
                    self._pipe_reader = reader
                    self._pipe_writer = writer
                except (FileNotFoundError, ConnectionRefusedError):
                    self.state = ConnectionState.DISCONNECTED
                    return False

            if not await self._authenticate_pipe():
                if self._pipe_writer:
                    self._pipe_writer.close()
                    try:
                        await self._pipe_writer.wait_closed()
                    except Exception:
                        pass
                self._pipe_reader = None
                self._pipe_writer = None
                self.state = ConnectionState.DISCONNECTED
                return False

            self.state = ConnectionState.CONNECTED
            self._read_task = asyncio.create_task(self._read_loop())
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            await self._flush_command_queue()
            return True

        except Exception:
            self.state = ConnectionState.DISCONNECTED
            return False

    async def _authenticate_pipe(self) -> bool:
        """Authenticate before marking a named-pipe connection as connected."""
        if not self.auth_token or not self._pipe_reader or not self._pipe_writer:
            return False

        seq = self._next_seq()
        hello = PipeMessage(
            msg_type=MsgType.HEARTBEAT,
            seq_id=seq,
            payload={"auth": self.auth_token},
        )
        self._pipe_writer.write(hello.pack())
        await self._pipe_writer.drain()

        try:
            header_bytes = await asyncio.wait_for(
                self._pipe_reader.readexactly(PipeMessage.HEADER_SIZE),
                timeout=3.0,
            )
            header = PipeHeader.unpack(header_bytes)
            payload = await asyncio.wait_for(
                self._pipe_reader.readexactly(header.payload_len),
                timeout=3.0,
            )
            response = PipeMessage.unpack(header_bytes + payload)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError):
            return False

        return (
            response.msg_type == MsgType.ACK
            and response.seq_id == seq
            and response.payload.get("authenticated") is True
        )

    async def _connect_http(self) -> bool:
        """Connect via HTTP (compatibility with existing x64dbg plugins)."""
        self.state = ConnectionState.CONNECTING
        session = None
        try:
            import aiohttp
            session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
            # Test connection
            async with session.get(f'{self.http_url}/status') as resp:
                if resp.status == 200:
                    self._http_session = session
                    self.state = ConnectionState.CONNECTED
                    self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
                    await self._flush_command_queue()
                    return True
        except Exception:
            pass

        # Clean up session on failure
        if session:
            await session.close()
        self.state = ConnectionState.DISCONNECTED
        return False

    async def disconnect(self):
        """Clean disconnect."""
        self.state = ConnectionState.DISCONNECTED
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._read_task:
            self._read_task.cancel()
        if self._pipe_writer:
            self._pipe_writer.close()
            try:
                await self._pipe_writer.wait_closed()
            except Exception:
                pass
        if self._http_session:
            await self._http_session.close()
        self._pipe_reader = None
        self._pipe_writer = None
        self._http_session = None

    async def reconnect(self):
        """Reconnect with exponential backoff. Concurrent callers share one attempt."""
        async with self._reconnect_lock:
            if self.state == ConnectionState.CONNECTED:
                return True
            await self.disconnect()
            self.state = ConnectionState.RECONNECTING
            for delay in self.RECONNECT_DELAYS:
                if await self.connect():
                    return True
                await asyncio.sleep(delay)
            self.state = ConnectionState.ERROR
            return False

    async def launch_x64dbg(self, target_exe: str = None, args: list = None,
                             wait_seconds: float = 3.0) -> bool:
        """
        Launch x64dbg (with optional target) and wait for it to be connectable.

        Args:
            target_exe: Path to the executable to debug (optional)
            args: Additional arguments for the target
            wait_seconds: How long to wait after launch before connecting

        Returns:
            True if x64dbg launched and connected successfully
        """
        import subprocess
        import shutil

        x64dbg = self.x64dbg_path
        if not x64dbg or not shutil.which(x64dbg) and not __import__('os.path', fromlist=['isfile']).isfile(x64dbg):
            raise FileNotFoundError(
                f"x64dbg not found at '{x64dbg}'.\n"
                "Set X64DBG_PATH environment variable or pass x64dbg_path to constructor."
            )

        cmd = [x64dbg]
        if target_exe:
            cmd += [target_exe]
            if args:
                cmd += args

        import sys as _sys
        _sys.stderr.write(f"[x64dbg] Launching: {' '.join(cmd)}\n")

        creationflags = 0
        if __import__('sys').platform == 'win32':
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

        if not self.auth_token:
            self.auth_token = secrets.token_hex(32)
        child_env = os.environ.copy()
        child_env["X64DBG_PIPE_TOKEN"] = self.auth_token

        self._x64dbg_proc = subprocess.Popen(
            cmd,
            creationflags=creationflags,
            env=child_env,
        )

        # Wait for x64dbg to start and the plugin to create the pipe
        await asyncio.sleep(wait_seconds)
        connected = await self.connect()
        if connected:
            _sys.stderr.write(f"[x64dbg] Connected (PID {self._x64dbg_proc.pid})\n")
        else:
            _sys.stderr.write(f"[x64dbg] Launched but not yet connected — try reconnect()\n")
        return connected

    def is_x64dbg_running(self) -> bool:
        """Check if our launched x64dbg process is still running."""
        if self._x64dbg_proc is None:
            return False
        return self._x64dbg_proc.poll() is None

    async def kill_x64dbg(self):
        """Terminate the x64dbg process launched by launch_x64dbg()."""
        await self.disconnect()
        if self._x64dbg_proc and self._x64dbg_proc.poll() is None:
            self._x64dbg_proc.terminate()
            try:
                self._x64dbg_proc.wait(timeout=5)
            except Exception:
                self._x64dbg_proc.kill()
        self._x64dbg_proc = None

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------
    async def send_command(self, command: str, args: dict = None, timeout: float = 10.0) -> dict:
        """Send a command to x64dbg and wait for response."""
        loop = asyncio.get_running_loop()
        args = args or {}

        if not self.connected:
            if self.protocol == BridgeProtocol.HTTP:
                # HTTP doesn't need pending futures — direct request/response
                return await self._send_http(command, args)

            seq = self._next_seq()
            future = loop.create_future()
            pending = PendingCommand(
                seq_id=seq, command=command,
                args=args, future=future, timeout=timeout,
            )
            self._command_queue.append(pending)
            if self._reconnect_task is None or self._reconnect_task.done():
                self._reconnect_task = asyncio.create_task(self.reconnect())
            try:
                return await asyncio.wait_for(future, timeout=timeout + 30)
            except asyncio.TimeoutError:
                return {"error": "Connection timeout"}

        # HTTP mode: direct request/response (no pipe futures needed)
        if self.protocol == BridgeProtocol.HTTP:
            return await self._send_http(command, args)

        # Pipe mode: send and wait for response via read loop
        seq = self._next_seq()
        future = loop.create_future()
        pending = PendingCommand(
            seq_id=seq, command=command,
            args=args, future=future, timeout=timeout,
        )
        self._pending[seq] = pending
        await self._send_pipe(command, args, seq)

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(seq, None)
            return {"error": f"Command timeout: {command}"}

    async def _send_pipe(self, command: str, args: dict, seq: int):
        """Send command via Named Pipe."""
        msg = PipeMessage(
            msg_type=MsgType.COMMAND,
            seq_id=seq,
            payload={"cmd": command, "args": args, "auth": self.auth_token},
        )
        self._pipe_writer.write(msg.pack())
        await self._pipe_writer.drain()

    async def _send_http(self, command: str, args: dict) -> dict:
        """Send command via HTTP."""
        try:
            async with self._http_session.post(
                f'{self.http_url}/command',
                json={"cmd": command, "args": args},
            ) as resp:
                return await resp.json()
        except Exception as e:
            return {"error": str(e)}

    async def _read_loop(self):
        """Read responses from Named Pipe."""
        try:
            while self.connected:
                header_bytes = await self._pipe_reader.readexactly(PipeMessage.HEADER_SIZE)
                header = PipeHeader.unpack(header_bytes)
                if header.payload_len > MAX_PAYLOAD_BYTES:
                    raise ValueError(f"Payload too large: {header.payload_len} bytes")
                payload = await self._pipe_reader.readexactly(header.payload_len)
                msg = PipeMessage.unpack(header_bytes + payload)

                if msg.msg_type == MsgType.RESPONSE:
                    pending = self._pending.pop(msg.seq_id, None)
                    if pending and not pending.future.done():
                        pending.future.set_result(msg.payload)

                elif msg.msg_type == MsgType.EVENT:
                    event_name = msg.payload.get("event", "unknown")
                    for handler in self._event_handlers.get(event_name, []):
                        try:
                            handler(msg.payload)
                        except Exception:
                            pass

                elif msg.msg_type == MsgType.HEARTBEAT:
                    # Respond with ACK
                    ack = PipeMessage(MsgType.ACK, msg.seq_id, {"auth": self.auth_token})
                    self._pipe_writer.write(ack.pack())
                    await self._pipe_writer.drain()

        except asyncio.IncompleteReadError:
            self.state = ConnectionState.DISCONNECTED
            if self._reconnect_task is None or self._reconnect_task.done():
                self._reconnect_task = asyncio.create_task(self.reconnect())
        except asyncio.CancelledError:
            pass
        except Exception:
            self.state = ConnectionState.DISCONNECTED
            if self._reconnect_task is None or self._reconnect_task.done():
                self._reconnect_task = asyncio.create_task(self.reconnect())

    async def _heartbeat_loop(self):
        """Send periodic heartbeats. Triggers reconnect on pipe failure."""
        try:
            while self.connected:
                await asyncio.sleep(5)
                if self.protocol == BridgeProtocol.NAMED_PIPE and self._pipe_writer:
                    msg = PipeMessage(
                        MsgType.HEARTBEAT,
                        self._next_seq(),
                        {"auth": self.auth_token},
                    )
                    try:
                        self._pipe_writer.write(msg.pack())
                        await self._pipe_writer.drain()
                    except Exception:
                        self.state = ConnectionState.DISCONNECTED
                        if self._reconnect_task is None or self._reconnect_task.done():
                            self._reconnect_task = asyncio.create_task(self.reconnect())
                        break
                elif self.protocol == BridgeProtocol.HTTP and self._http_session:
                    try:
                        async with self._http_session.get(f'{self.http_url}/status') as resp:
                            if resp.status != 200:
                                self.state = ConnectionState.DISCONNECTED
                                if self._reconnect_task is None or self._reconnect_task.done():
                                    self._reconnect_task = asyncio.create_task(self.reconnect())
                                break
                    except Exception:
                        self.state = ConnectionState.DISCONNECTED
                        if self._reconnect_task is None or self._reconnect_task.done():
                            self._reconnect_task = asyncio.create_task(self.reconnect())
                        break
        except asyncio.CancelledError:
            pass

    async def _flush_command_queue(self):
        """Send queued commands after reconnection."""
        while self._command_queue:
            pending = self._command_queue.pop(0)
            self._pending[pending.seq_id] = pending
            if self.protocol == BridgeProtocol.NAMED_PIPE:
                await self._send_pipe(pending.command, pending.args, pending.seq_id)
            else:
                result = await self._send_http(pending.command, pending.args)
                if not pending.future.done():
                    pending.future.set_result(result)

    # ------------------------------------------------------------------
    # Event subscription
    # ------------------------------------------------------------------
    def on_event(self, event: str, handler: Callable):
        """Subscribe to debugger events (breakpoint hit, exception, etc.)."""
        self._event_handlers.setdefault(event, []).append(handler)

    # ------------------------------------------------------------------
    # High-level debugging API
    # ------------------------------------------------------------------
    async def get_registers(self) -> Optional[dict]:
        """Get all CPU registers."""
        result = await self.send_command("registers.get_all")
        return result if "error" not in result else None

    async def set_register(self, name: str, value: int) -> bool:
        result = await self.send_command("registers.set", {"name": name, "value": value})
        return "error" not in result

    async def get_debug_status(self) -> Optional[str]:
        result = await self.send_command("debug.status")
        return result.get("status") if "error" not in result else None

    async def step_into(self) -> dict:
        return await self.send_command("debug.step_into")

    async def step_over(self) -> dict:
        return await self.send_command("debug.step_over")

    async def run(self) -> dict:
        return await self.send_command("debug.run")

    async def pause(self) -> dict:
        return await self.send_command("debug.pause")

    async def set_breakpoint(self, address: int, bp_type: str = "software") -> dict:
        return await self.send_command("breakpoint.set", {
            "address": address, "type": bp_type,
        })

    async def delete_breakpoint(self, address: int) -> dict:
        return await self.send_command("breakpoint.delete", {"address": address})

    async def set_hardware_breakpoint(self, address: int, size: int = 1,
                                       condition: str = "execute") -> dict:
        return await self.send_command("breakpoint.set_hardware", {
            "address": address, "size": size, "condition": condition,
        })

    async def read_memory(self, address: int, size: int) -> Optional[bytes]:
        result = await self.send_command("memory.read", {
            "address": address, "size": size,
        })
        if "error" in result:
            return None
        # Decode hex-encoded memory
        hex_data = result.get("data", "")
        return bytes.fromhex(hex_data) if hex_data else None

    async def write_memory(self, address: int, data: bytes) -> bool:
        result = await self.send_command("memory.write", {
            "address": address, "data": data.hex(),
        })
        return "error" not in result

    async def read_memory_string(self, address: int, max_len: int = 256) -> Optional[str]:
        data = await self.read_memory(address, max_len)
        if data is None:
            return None
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode('utf-8', errors='replace')

    async def disassemble(self, address: int, count: int = 20) -> list[dict]:
        result = await self.send_command("disasm.get", {
            "address": address, "count": count,
        })
        return result.get("instructions", []) if "error" not in result else []

    async def get_memory_map(self) -> list[dict]:
        result = await self.send_command("memory.map")
        return result.get("regions", []) if "error" not in result else []

    async def get_modules(self) -> list[dict]:
        result = await self.send_command("modules.list")
        return result.get("modules", []) if "error" not in result else []

    async def get_call_stack(self) -> list[dict]:
        result = await self.send_command("stack.callstack")
        return result.get("frames", []) if "error" not in result else []

    async def get_threads(self) -> list[dict]:
        result = await self.send_command("threads.list")
        return result.get("threads", []) if "error" not in result else []

    async def search_pattern(self, pattern: str, module: str = None) -> list[dict]:
        args = {"pattern": pattern}
        if module:
            args["module"] = module
        result = await self.send_command("memory.search_pattern", args)
        return result.get("results", []) if "error" not in result else []

    async def search_strings(self, min_length: int = 4) -> list[dict]:
        result = await self.send_command("memory.search_strings", {"min_length": min_length})
        return result.get("strings", []) if "error" not in result else []

    async def get_imports(self, module: str = None) -> list[dict]:
        args = {"module": module} if module else {}
        result = await self.send_command("symbols.imports", args)
        return result.get("imports", []) if "error" not in result else []

    async def get_exports(self, module: str = None) -> list[dict]:
        args = {"module": module} if module else {}
        result = await self.send_command("symbols.exports", args)
        return result.get("exports", []) if "error" not in result else []

    async def analyze_function(self, address: int) -> dict:
        return await self.send_command("analysis.function", {"address": address})

    async def get_xrefs_to(self, address: int) -> list[dict]:
        result = await self.send_command("analysis.xrefs_to", {"address": address})
        return result.get("xrefs", []) if "error" not in result else []

    async def get_xrefs_from(self, address: int) -> list[dict]:
        result = await self.send_command("analysis.xrefs_from", {"address": address})
        return result.get("xrefs", []) if "error" not in result else []

    async def set_comment(self, address: int, comment: str) -> bool:
        result = await self.send_command("annotations.comment", {
            "address": address, "comment": comment,
        })
        return "error" not in result

    async def set_label(self, address: int, label: str) -> bool:
        result = await self.send_command("annotations.label", {
            "address": address, "label": label,
        })
        return "error" not in result

    @staticmethod
    def _coerce_int(value) -> Optional[int]:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 16) if value.lower().startswith("0x") else int(value)
            except ValueError:
                return None
        return None

    async def evaluate_expression(self, expression: str) -> Optional[int]:
        result = await self.send_command("eval", {"expression": expression})
        if "error" in result:
            return None
        return self._coerce_int(result.get("value_dec", result.get("value")))

    async def eval_expression(self, expr: str) -> dict:
        """Evaluate an expression. Aliases the plugin ``eval`` command."""
        result = await self.send_command("eval", {"expression": expr})
        coerced = self._coerce_int(result.get("value_dec", result.get("value")))
        if coerced is not None:
            result = dict(result)
            result["value"] = coerced
            result.setdefault("hex", hex(coerced))
        return result

    async def execute_command(self, command: str) -> dict:
        """Execute a raw x64dbg command."""
        return await self.send_command("command.execute", {"command": command})

    async def get_peb(self) -> dict:
        """Get Process Environment Block info."""
        return await self.send_command("process.peb")

    async def allocate_memory(self, size: int, protection: int = 0x40) -> Optional[int]:
        result = await self.send_command("memory.allocate", {
            "size": size, "protection": protection,
        })
        return result.get("address") if "error" not in result else None

    async def set_memory_protection(self, address: int, size: int, protection: int) -> bool:
        result = await self.send_command("memory.protect", {
            "address": address, "size": size, "protection": protection,
        })
        return "error" not in result

    async def dump_module(self, module: str, output_path: str) -> bool:
        result = await self.send_command("dump.module", {
            "module": module, "output": output_path,
        })
        return "error" not in result

    async def get_handles(self) -> list[dict]:
        result = await self.send_command("process.handles")
        return result.get("handles", []) if "error" not in result else []

    async def hide_bossix(self) -> bool:
        result = await self.send_command("bossix.hide")
        return "error" not in result

    async def run_script(self, script: str) -> dict:
        """Execute x64dbg script commands."""
        return await self.send_command("script.run", {"script": script})
