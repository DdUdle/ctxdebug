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
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Optional

log = logging.getLogger("x64dbg.bridge")


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
# Wire protocol for Named Pipes
# ------------------------------------------------------------------
# Header: [magic(4)] [version(2)] [msg_type(2)] [payload_len(4)] [seq_id(4)]
# Payload: JSON-encoded command/response

PIPE_MAGIC = b'X64A'
PIPE_VERSION = 1

class MsgType(IntEnum):
    COMMAND = 0x01
    RESPONSE = 0x02
    EVENT = 0x03
    HEARTBEAT = 0x04
    ACK = 0x05
    ERROR = 0xFF


@dataclass
class PipeMessage:
    msg_type: MsgType
    seq_id: int
    payload: dict

    HEADER_SIZE = 16  # 4 + 2 + 2 + 4 + 4

    def pack(self) -> bytes:
        payload_bytes = json.dumps(self.payload).encode('utf-8')
        header = struct.pack('<4sHHII',
            PIPE_MAGIC,
            PIPE_VERSION,
            self.msg_type,
            len(payload_bytes),
            self.seq_id,
        )
        return header + payload_bytes

    @classmethod
    def unpack(cls, data: bytes) -> 'PipeMessage':
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Incomplete message header")
        magic, version, msg_type, payload_len, seq_id = struct.unpack(
            '<4sHHII', data[:cls.HEADER_SIZE]
        )
        if magic != PIPE_MAGIC:
            raise ValueError(f"Invalid magic: {magic}")
        payload_bytes = data[cls.HEADER_SIZE:cls.HEADER_SIZE + payload_len]
        payload = json.loads(payload_bytes) if payload_bytes else {}
        return cls(msg_type=MsgType(msg_type), seq_id=seq_id, payload=payload)


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
                 x64dbg_path: str = None):
        self.pipe_name = pipe_name or self.PIPE_NAME
        self.http_url = http_url or self.HTTP_URL
        self.protocol = protocol
        self.x64dbg_path = x64dbg_path or self.X64DBG_PATH
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
        """Connect to x64dbg. Tries Named Pipe first, falls back to HTTP."""
        if self.protocol == BridgeProtocol.NAMED_PIPE:
            if await self._connect_pipe():
                return True
            # Fallback to HTTP
            self.protocol = BridgeProtocol.HTTP

        if self.protocol == BridgeProtocol.HTTP:
            return await self._connect_http()

        return False

    async def _connect_pipe(self) -> bool:
        """Connect via Windows Named Pipe (or Unix socket for dev/testing)."""
        self.state = ConnectionState.CONNECTING
        try:
            import sys
            if sys.platform == 'win32':
                # Windows: open Named Pipe as a file-like object via proactor loop
                import ctypes
                import ctypes.wintypes as wt

                GENERIC_READ = 0x80000000
                GENERIC_WRITE = 0x40000000
                OPEN_EXISTING = 3
                INVALID = ctypes.c_void_p(-1).value

                pipe_path = self.pipe_name.encode('utf-8') if isinstance(self.pipe_name, str) else self.pipe_name

                handle = ctypes.windll.kernel32.CreateFileW(
                    self.pipe_name,
                    GENERIC_READ | GENERIC_WRITE,
                    0,       # no sharing
                    None,    # default security
                    OPEN_EXISTING,
                    0x40000000,  # FILE_FLAG_OVERLAPPED
                    None,
                )
                if handle == INVALID:
                    err = ctypes.windll.kernel32.GetLastError()
                    log.warning("Named pipe %s not available (CreateFileW GetLastError=%d)",
                                self.pipe_name, err)
                    self.state = ConnectionState.DISCONNECTED
                    return False

                # Wrap the Win32 handle in asyncio streams via ProactorEventLoop
                loop = asyncio.get_running_loop()
                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await loop._make_socket_transport(
                    handle, protocol, extra={'peername': self.pipe_name}
                )
                writer = asyncio.StreamWriter(transport, protocol, reader, loop)
                self._pipe_reader = reader
                self._pipe_writer = writer
            else:
                # Unix socket fallback for development/testing
                sock_path = self.pipe_name if self.pipe_name.startswith('/') else '/tmp/x64dbg_ai_agent.sock'
                try:
                    reader, writer = await asyncio.open_unix_connection(sock_path)
                    self._pipe_reader = reader
                    self._pipe_writer = writer
                except (FileNotFoundError, ConnectionRefusedError) as e:
                    log.warning("Unix socket %s not available: %s", sock_path, e)
                    self.state = ConnectionState.DISCONNECTED
                    return False

            self.state = ConnectionState.CONNECTED
            self._read_task = asyncio.create_task(self._read_loop())
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            await self._flush_command_queue()
            return True

        except Exception:
            log.exception("Pipe connection to %s failed", self.pipe_name)
            self.state = ConnectionState.DISCONNECTED
            return False

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
                log.warning("HTTP status probe to %s returned %d", self.http_url, resp.status)
        except Exception:
            log.exception("HTTP connection to %s failed", self.http_url)

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
        """Reconnect with exponential backoff."""
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

        self._x64dbg_proc = subprocess.Popen(
            cmd,
            creationflags=creationflags,
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
            asyncio.create_task(self.reconnect())
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
            payload={"cmd": command, "args": args},
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
                header = await self._pipe_reader.readexactly(PipeMessage.HEADER_SIZE)
                _, _, _, payload_len, _ = struct.unpack('<4sHHII', header)
                payload = await self._pipe_reader.readexactly(payload_len)
                data = header + payload

                msg = PipeMessage.unpack(data)

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
                            log.exception("Event handler for %r raised", event_name)

                elif msg.msg_type == MsgType.HEARTBEAT:
                    # Respond with ACK
                    ack = PipeMessage(MsgType.ACK, msg.seq_id, {})
                    self._pipe_writer.write(ack.pack())
                    await self._pipe_writer.drain()

        except asyncio.IncompleteReadError:
            self.state = ConnectionState.DISCONNECTED
            asyncio.create_task(self.reconnect())
        except asyncio.CancelledError:
            pass

    async def _heartbeat_loop(self):
        """Send periodic heartbeats. Triggers reconnect on pipe failure."""
        try:
            while self.connected:
                await asyncio.sleep(5)
                if self.protocol == BridgeProtocol.NAMED_PIPE and self._pipe_writer:
                    msg = PipeMessage(MsgType.HEARTBEAT, self._next_seq(), {})
                    try:
                        self._pipe_writer.write(msg.pack())
                        await self._pipe_writer.drain()
                    except Exception:
                        self.state = ConnectionState.DISCONNECTED
                        asyncio.create_task(self.reconnect())
                        break
                elif self.protocol == BridgeProtocol.HTTP and self._http_session:
                    try:
                        async with self._http_session.get(f'{self.http_url}/status') as resp:
                            if resp.status != 200:
                                self.state = ConnectionState.DISCONNECTED
                                asyncio.create_task(self.reconnect())
                                break
                    except Exception:
                        self.state = ConnectionState.DISCONNECTED
                        asyncio.create_task(self.reconnect())
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

    async def evaluate_expression(self, expression: str) -> Optional[int]:
        result = await self.send_command("eval", {"expression": expression})
        return result.get("value") if "error" not in result else None

    async def eval_expression(self, expr: str) -> dict:
        """Evaluate an expression via the eval_expression plugin command.

        Sends {"cmd": "eval_expression", "args": {"expression": expr}} through
        the named pipe.  Returns the raw response dict — callers check for
        "value" (numeric result) or "error" key.
        """
        return await self.send_command("eval_expression", {"expression": expr})

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
