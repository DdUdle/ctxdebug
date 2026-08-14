#!/usr/bin/env python3
"""
WinDbg MCP server for Claude Code.

Stdio JSON-RPC MCP server that wraps `cdb.exe` (console WinDbg).
No third-party dependencies — only the Python stdlib.

Why cdb? It is the headless console version of WinDbg, ships with the
Debugging Tools for Windows, accepts the same commands as WinDbg, and
streams text on stdin/stdout — perfect for an MCP backend.

Add to Claude Code:
    claude mcp add windbg -- python "C:\\path\\to\\windbg_mcp.py"

Optionally point at a specific cdb.exe:
    set WINDBG_MCP_CDB=C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe

Workflow from the model side:
    1. windbg_start_executable / windbg_attach / windbg_open_dump
    2. windbg_status to see where we are
    3. set breakpoints, step, inspect registers / stack / memory
    4. windbg_stop when done
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from queue import Empty, Queue
from typing import Any, Callable

from mco_common import kv_block as _kv_block, section as _section

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "windbg"
SERVER_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# cdb subprocess wrapper
# ---------------------------------------------------------------------------

CDB_PROMPT_RE = re.compile(r"^\d+:\d+(:[0-9a-f]+)?>\s*$")
CDB_PROMPT_PREFIX_RE = re.compile(r"^\d+:\d+(:[0-9a-f]+)?>\s*")
CDB_EXCEPTION_RE = re.compile(
    r"(\([0-9a-fA-F.]+:[0-9a-fA-F.]+\): .*exception - code|"
    r"access violation|c0000005|heap_corruption|heap corruption|c0000374|"
    r"failfast|fast_fail|fatal error)",
    re.IGNORECASE,
)


def _find_cdb() -> str:
    env = os.environ.get("WINDBG_MCP_CDB")
    if env and os.path.isfile(env):
        return env
    found = shutil.which("cdb") or shutil.which("cdb.exe")
    if found:
        return found
    candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe",
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
        r"C:\Program Files (x86)\Debugging Tools for Windows (x64)\cdb.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return "cdb.exe"


class CdbSession:
    def __init__(self) -> None:
        self.cdb_path = _find_cdb()
        self.proc: subprocess.Popen[str] | None = None
        self.lock = threading.Lock()
        self.out_q: Queue[str | None] = Queue()
        self.target_desc: str = ""
        self.symbol_path: str | None = os.environ.get("_NT_SYMBOL_PATH")
        self.async_command: str | None = None
        self.async_started_at: float | None = None

    # ----- lifecycle -------------------------------------------------------
    def clear_async_state(self) -> None:
        self.async_command = None
        self.async_started_at = None

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _spawn(self, args: list[str]) -> str:
        if self.is_running():
            raise RuntimeError("cdb session already active. Call windbg_stop first.")
        cmd = [self.cdb_path] + args
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            errors="replace",
            creationflags=creationflags,
        )
        self.out_q = Queue()
        t = threading.Thread(target=self._read_loop, daemon=True)
        t.start()
        banner = self._collect_until_prompt(timeout=60)
        return banner

    def start_executable(self, exe: str, args: list[str] | None = None) -> str:
        cdb_args: list[str] = []
        if self.symbol_path:
            cdb_args += ["-y", self.symbol_path]
        # cdb uses: cdb.exe [options] <exe> [args...]
        # -o: debug child processes too
        cdb_args += [exe] + (args or [])
        return self._spawn(cdb_args)

    def attach_pid(self, pid: int) -> str:
        cdb_args: list[str] = []
        if self.symbol_path:
            cdb_args += ["-y", self.symbol_path]
        cdb_args += ["-p", str(pid)]
        return self._spawn(cdb_args)

    def open_dump(self, path: str) -> str:
        cdb_args: list[str] = []
        if self.symbol_path:
            cdb_args += ["-y", self.symbol_path]
        cdb_args += ["-z", path]
        return self._spawn(cdb_args)

    def stop(self) -> str:
        if not self.is_running():
            self.proc = None
            return "no active session"
        try:
            assert self.proc and self.proc.stdin
            self.proc.stdin.write("q\n")
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            assert self.proc
            self.proc.wait(timeout=5)
        except Exception:
            try:
                assert self.proc
                self.proc.kill()
            except Exception:
                pass
        self.proc = None
        self.target_desc = ""
        self.clear_async_state()
        return "session terminated"

    def break_in(self) -> str:
        if not self.is_running():
            return "no active session"
        try:
            if os.name == "nt":
                import signal

                assert self.proc
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                self.clear_async_state()
                return "CTRL_BREAK sent"
            else:
                assert self.proc and self.proc.stdin
                self.proc.stdin.write("\x03")
                self.proc.stdin.flush()
                self.clear_async_state()
                return "SIGINT sent via stdin"
        except Exception as e:
            return f"break failed: {e}"

    # ----- I/O -------------------------------------------------------------
    def _read_loop(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            for line in iter(self.proc.stdout.readline, ""):
                if line == "":
                    break
                self.out_q.put(line)
        except Exception:
            pass
        finally:
            self.out_q.put(None)

    def _collect_until_prompt(self, timeout: float = 30.0) -> str:
        out: list[str] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self.out_q.get(timeout=0.5)
            except Empty:
                continue
            if line is None:
                break
            stripped = line.rstrip("\n")
            if CDB_PROMPT_RE.match(stripped):
                break
            out.append(stripped)
        return "\n".join(out)

    def _collect_until_marker(self, marker: str, timeout: float) -> tuple[str, bool]:
        """Returns (text, completed). completed=False on timeout."""
        out: list[str] = []
        deadline = time.time() + timeout
        completed = False
        while time.time() < deadline:
            try:
                line = self.out_q.get(timeout=0.5)
            except Empty:
                continue
            if line is None:
                break
            stripped = line.rstrip("\n")
            if marker in stripped:
                completed = True
                break
            cleaned = CDB_PROMPT_PREFIX_RE.sub("", stripped).rstrip()
            out.append(cleaned)
        while out and not out[0].strip():
            out.pop(0)
        while out and not out[-1].strip():
            out.pop()
        return "\n".join(out), completed

    def _trim_output(self, out: list[str]) -> str:
        while out and not out[0].strip():
            out.pop(0)
        while out and not out[-1].strip():
            out.pop()
        return "\n".join(out)

    def _collect_async_output(
        self,
        timeout: float = 0.0,
        max_lines: int | None = None,
        stop_on_prompt: bool = False,
        quiet_timeout: float | None = None,
        stop_on_exception: bool = False,
    ) -> tuple[str, bool, bool, bool, bool]:
        """Return (text, saw_prompt, process_exited, quiet_after_output, saw_exception) without break-in."""
        out: list[str] = []
        saw_prompt = False
        process_exited = False
        quiet_after_output = False
        saw_exception = False
        deadline = time.time() + max(timeout, 0.0)
        last_output_at: float | None = None
        while True:
            remaining = deadline - time.time()
            quiet_is_armed = last_output_at is not None and (not stop_on_exception or saw_exception)
            if (
                quiet_timeout is not None
                and quiet_is_armed
                and time.time() - last_output_at >= quiet_timeout
            ):
                quiet_after_output = True
                break
            wait = min(0.5, remaining) if timeout > 0 else 0
            try:
                line = self.out_q.get(timeout=max(wait, 0))
            except Empty:
                if (
                    quiet_timeout is not None
                    and quiet_is_armed
                    and time.time() - last_output_at >= quiet_timeout
                ):
                    quiet_after_output = True
                    break
                if timeout <= 0 or time.time() >= deadline:
                    break
                continue
            if line is None:
                process_exited = True
                break
            stripped = line.rstrip("\n")
            if CDB_PROMPT_RE.match(stripped):
                saw_prompt = True
                if stop_on_prompt:
                    break
                continue
            cleaned = CDB_PROMPT_PREFIX_RE.sub("", stripped).rstrip()
            out.append(cleaned)
            if CDB_EXCEPTION_RE.search(cleaned):
                saw_exception = True
            last_output_at = time.time()
            if max_lines is not None and len(out) >= max_lines:
                break
        if saw_prompt or process_exited or saw_exception:
            self.clear_async_state()
        return self._trim_output(out), saw_prompt, process_exited, quiet_after_output, saw_exception

    def run(self, command: str, timeout: float = 60.0, recover_on_timeout: bool = True) -> str:
        if not self.is_running():
            raise RuntimeError("No active cdb session. Use windbg_start_executable / windbg_attach / windbg_open_dump.")
        if self.async_command:
            raise RuntimeError(
                f"async command still active: {self.async_command!r}. "
                "Use windbg_wait_for_event / windbg_read_output, or windbg_break_in."
            )
        marker = f"__WBMCP_DONE_{uuid.uuid4().hex}__"
        with self.lock:
            assert self.proc and self.proc.stdin
            self.proc.stdin.write(f"{command}\n.echo {marker}\n")
            self.proc.stdin.flush()
            text, completed = self._collect_until_marker(marker, timeout=timeout)
            if completed:
                return text
            # Timed out. cdb is still running the command (typically `g`).
            # Break in to recover the prompt, then drain until our marker echoes.
            if recover_on_timeout:
                try:
                    if os.name == "nt":
                        import signal
                        assert self.proc
                        self.proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                    else:
                        self.proc.stdin.write("\x03")
                        self.proc.stdin.flush()
                except Exception:
                    pass
                tail, completed2 = self._collect_until_marker(marker, timeout=10)
                suffix = "\n[TIMEOUT after {}s — break-in sent, target paused]".format(int(timeout))
                if tail:
                    text = (text + "\n" + tail).strip("\n")
                if not completed2:
                    suffix += " [marker still pending — cdb may be stuck]"
                return text + suffix
            return text + f"\n[TIMEOUT after {int(timeout)}s — output may be truncated]"


    def run_async(self, command: str) -> str:
        if not self.is_running():
            raise RuntimeError("No active cdb session. Use windbg_start_executable / windbg_attach / windbg_open_dump.")
        with self.lock:
            if self.async_command:
                raise RuntimeError(
                    f"async command already active: {self.async_command!r}. "
                    "Read it with windbg_wait_for_event / windbg_read_output first."
                )
            assert self.proc and self.proc.stdin
            self.proc.stdin.write(f"{command}\n")
            self.proc.stdin.flush()
            self.async_command = command
            self.async_started_at = time.time()
        return f"started async command: {command}"

    def read_output(self, max_lines: int | None = 50) -> tuple[str, bool, bool]:
        text, saw_prompt, process_exited, _, _ = self._collect_async_output(timeout=0.0, max_lines=max_lines, stop_on_prompt=False)
        return text, saw_prompt, process_exited

    def wait_for_event(
        self,
        timeout: float = 120.0,
        max_lines: int | None = None,
        quiet_timeout: float | None = 1.0,
        stop_on_exception: bool = False,
    ) -> tuple[str, bool, bool, bool, bool]:
        return self._collect_async_output(
            timeout=timeout,
            max_lines=max_lines,
            stop_on_prompt=True,
            quiet_timeout=quiet_timeout,
            stop_on_exception=stop_on_exception,
        )


SESSION = CdbSession()


# ---------------------------------------------------------------------------
# Output formatting helpers
# ---------------------------------------------------------------------------


def _strip_prompts(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not CDB_PROMPT_RE.match(line.strip())
    )


def _strip_prompt_prefix(line: str) -> str:
    return CDB_PROMPT_PREFIX_RE.sub("", line).strip()


def _filter_output(
    text: str,
    filter_pattern: str | None = None,
    max_lines: int | None = None,
    drop_pattern: str | None = None,
    exclude_pattern: str | None = None,
    ignore_case: bool = False,
    invert_match: bool = False,
    context_before: int = 0,
    context_after: int = 0,
    tail_lines: int | None = None,
) -> str:
    lines = text.splitlines()
    flags = re.IGNORECASE if ignore_case else 0
    if drop_pattern:
        try:
            drop_re = re.compile(drop_pattern, re.IGNORECASE)
        except re.error as e:
            return f"[FILTER ERROR: invalid drop_pattern: {e}]\n{text}"
        lines = [line for line in lines if not drop_re.search(line)]
    if exclude_pattern:
        try:
            exclude_re = re.compile(exclude_pattern, flags)
        except re.error as e:
            return f"[FILTER ERROR: invalid exclude_pattern: {e}]\n{text}"
        lines = [line for line in lines if not exclude_re.search(line)]
    if filter_pattern:
        try:
            keep_re = re.compile(filter_pattern, flags)
        except re.error as e:
            return f"[FILTER ERROR: invalid filter_pattern: {e}]\n{text}"
        matched: list[int] = []
        for i, line in enumerate(lines):
            is_match = bool(keep_re.search(line))
            if is_match != invert_match:
                matched.append(i)
        if context_before > 0 or context_after > 0:
            selected: set[int] = set()
            for i in matched:
                start = max(0, i - max(context_before, 0))
                end = min(len(lines), i + max(context_after, 0) + 1)
                selected.update(range(start, end))
            lines = [line for i, line in enumerate(lines) if i in selected]
        else:
            lines = [lines[i] for i in matched]
    if tail_lines is not None and tail_lines >= 0:
        lines = lines[-tail_lines:]
    if max_lines is not None and max_lines >= 0:
        lines = lines[:max_lines]
    return "\n".join(lines)


def _filter_address_noise(text: str, max_lines: int | None = None) -> str:
    return _filter_output(
        text,
        max_lines=max_lines,
        drop_pattern=r"Building memory map|^Mapping .*regions\.\.\.$",
    )


def _filter_heap_noise(text: str) -> str:
    return _filter_output(
        text,
        drop_pattern=r"(!heap\s+-p.*commands.*replaced|exts\.dll.*replaced|use.*extsheap)",
    )


def _split_cdb_commands(command: str) -> list[str]:
    commands: list[str] = []
    current: list[str] = []
    in_quote = False
    escape = False
    for ch in command:
        if ch == "\\" and in_quote:
            escape = not escape
            current.append(ch)
            continue
        if ch == '"' and not escape:
            in_quote = not in_quote
            current.append(ch)
            continue
        escape = False
        if ch == ";" and not in_quote:
            item = "".join(current).strip()
            if item:
                commands.append(item)
            current = []
            continue
        current.append(ch)
    item = "".join(current).strip()
    if item:
        commands.append(item)
    return commands


def _cdb_bp_quote(command: str) -> str:
    return '"' + command.replace('"', r'\"') + '"'


def _bp_printf(label: str, expression: str) -> str:
    safe_label = label.replace("\\", "\\\\").replace('"', r'\"')
    safe_expr = expression.replace("\\", "\\\\").replace('"', r'\"')
    return f'.printf "{safe_label}: {safe_expr}=%p\\n", {expression}'


_REG_SIGN_BITS = {
    "eax": "0x80000000",
    "ebx": "0x80000000",
    "ecx": "0x80000000",
    "edx": "0x80000000",
    "esi": "0x80000000",
    "edi": "0x80000000",
    "esp": "0x80000000",
    "ebp": "0x80000000",
    "eip": "0x80000000",
}


def _rewrite_signed_negative_condition(condition: str) -> tuple[str, bool]:
    def repl(match: re.Match[str]) -> str:
        reg = match.group("reg")
        reg_name = reg[1:].lower()
        mask = _REG_SIGN_BITS.get(reg_name, "0x8000000000000000")
        return f"(({reg} & {mask}) != 0)"

    rewritten = re.sub(
        r"(?P<reg>@(?:[a-zA-Z][a-zA-Z0-9]*|\$[a-zA-Z0-9_]+))\s*<\s*0(?![xX0-9a-fA-F])",
        repl,
        condition,
    )
    return rewritten, rewritten != condition


def _breakpoint_store_dir() -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".windbg_mcp_breakpoints")
    os.makedirs(path, exist_ok=True)
    return path


def _safe_name(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name.strip())
    return safe or "default"


def _parse_db_bytes(raw: str) -> bytes:
    values: list[int] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        byte_part = parts[1].split("  ", 1)[0].replace("-", " ")
        for token in re.findall(r"\b[0-9a-fA-F]{2}\b", byte_part):
            values.append(int(token, 16))
    return bytes(values)


def _parse_address_hits(raw: str, max_hits: int) -> list[str]:
    hits: list[str] = []
    for line in raw.splitlines():
        m = re.match(r"\s*([0-9a-fA-F`]{8,})\s+([0-9a-fA-F`]{8,})\b", line)
        if not m:
            continue
        addr = m.group(1)
        if addr not in hits:
            hits.append(addr)
        if len(hits) >= max_hits:
            break
    return hits


def _parse_cdb_int(value: str) -> int:
    cleaned = value.replace("`", "").replace("_", "").strip()
    if cleaned.lower().startswith("0x"):
        return int(cleaned, 16)
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and re.search(r"[a-fA-F]", cleaned):
        return int(cleaned, 16)
    return int(cleaned, 16)


def _format_cdb_hex(value: int) -> str:
    hi = value >> 32
    lo = value & 0xFFFFFFFF
    return f"{hi:08x}`{lo:08x}"


def _parse_heap_ranges_from_address(raw: str) -> list[tuple[int, int]]:
    """Parse ranges from !address -f:Heap across table and verbose formats."""
    ranges: list[tuple[int, int]] = []

    def add_range(start: int, length: int) -> None:
        if start <= 0 or length <= 0:
            return
        item = (start, length)
        if item not in ranges:
            ranges.append(item)

    for line in raw.splitlines():
        if "Heap" not in line:
            continue
        m = re.match(r"\s*([0-9a-fA-F`]{8,})\s+([0-9a-fA-F`]{8,})\s+([0-9a-fA-F`]+)\b", line)
        if not m:
            continue
        try:
            start = _parse_cdb_int(m.group(1))
            third = _parse_cdb_int(m.group(3))
        except ValueError:
            continue
        add_range(start, third)

    current: dict[str, int | str] = {}
    for line in raw.splitlines() + [""]:
        stripped = line.strip()
        if not stripped:
            if current.get("usage") == "Heap" and "base" in current:
                base = int(current["base"])
                if "size" in current:
                    add_range(base, int(current["size"]))
                elif "end" in current:
                    add_range(base, int(current["end"]) - base)
            current = {}
            continue
        m = re.match(r"Base Address:\s*([0-9a-fA-F`]+)", stripped, re.IGNORECASE)
        if m:
            current["base"] = _parse_cdb_int(m.group(1))
            continue
        m = re.match(r"End Address:\s*([0-9a-fA-F`]+)", stripped, re.IGNORECASE)
        if m:
            current["end"] = _parse_cdb_int(m.group(1))
            continue
        m = re.match(r"Region Size:\s*([0-9a-fA-F`]+)", stripped, re.IGNORECASE)
        if m:
            current["size"] = _parse_cdb_int(m.group(1))
            continue
        m = re.match(r"Usage:\s*(\S+)", stripped, re.IGNORECASE)
        if m:
            current["usage"] = m.group(1)

    return ranges


def _parse_heap_user_block(raw: str) -> tuple[int | None, int | None]:
    for line in raw.splitlines():
        m = re.search(
            r"\b([0-9a-fA-F`]{8,})\s+([0-9a-fA-F`]{1,8})\s*-\s*\((?:busy|free)\)",
            line,
            re.IGNORECASE,
        )
        if not m:
            continue
        try:
            return _parse_cdb_int(m.group(1)), _parse_cdb_int(m.group(2))
        except ValueError:
            continue
    return None, None


def _parse_dps_rows(raw: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in raw.splitlines():
        m = re.match(r"\s*([0-9a-fA-F`]{8,})\s+([0-9a-fA-F`]{8,})(?:\s+(.*))?$", line)
        if not m:
            continue
        rows.append((m.group(1), m.group(2), (m.group(3) or "").strip()))
    return rows


def _shadow_slot_expr(index: int) -> str:
    offset = max(index, 0) * 8
    return "@ssp" if offset == 0 else f"@ssp+0x{offset:x}"


def _normalize_cdb_expr(expr: str) -> str:
    return re.sub(r"@\$([a-zA-Z][a-zA-Z0-9]*)", r"@\1", expr.strip())


def _read_ssp() -> tuple[str, int | None]:
    raw = SESSION.run("r @ssp", timeout=10)
    m = re.search(r"\bssp=([0-9a-fA-F`]+)", raw)
    if not m:
        return raw, None
    try:
        return raw, _parse_cdb_int(m.group(1))
    except ValueError:
        return raw, None


_DISASM_LINE_RE = re.compile(r"^[0-9a-fA-F`]{8,}\s+[0-9a-fA-F]{2,}\s+[a-z]{2,}")


def parse_registers(raw: str) -> dict[str, str]:
    """Parse `r` output into name->value map.

    cdb prints rax=... rbx=... etc., plus a symbol line ending with ':'
    and a disassembly line `00007ff`abcd1234 488bc4 mov ...`. We skip both.
    """
    regs: dict[str, str] = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        if _DISASM_LINE_RE.match(line.strip()):
            continue
        # symbol line like `module!Func+0x1:` ends with `:` and has no `=`
        for m in re.finditer(r"\b([a-z][a-z0-9]{1,6})=([0-9a-fA-F`]+)", line):
            regs[m.group(1)] = m.group(2)
    return regs


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _need_session() -> str | None:
    if not SESSION.is_running():
        return "ERROR: no active cdb session. Start one with windbg_start_executable, windbg_attach, or windbg_open_dump."
    return None


# ----- session lifecycle ----------------------------------------------------


def tool_start_executable(exe: str, args: list[str] | None = None) -> str:
    if SESSION.is_running():
        return "ERROR: a session is already active. Call windbg_stop first."
    try:
        banner = SESSION.start_executable(exe, args)
    except FileNotFoundError:
        return f"ERROR: cdb not found at '{SESSION.cdb_path}'. Set WINDBG_MCP_CDB to its full path."
    SESSION.target_desc = f"executable: {exe} {' '.join(args or [])}".strip()
    status = tool_status()
    return _section("LAUNCHED", SESSION.target_desc) + "\n\n" + _section("CDB BANNER", banner) + "\n\n" + status


def tool_attach(pid: int) -> str:
    if SESSION.is_running():
        return "ERROR: a session is already active."
    try:
        banner = SESSION.attach_pid(pid)
    except FileNotFoundError:
        return f"ERROR: cdb not found at '{SESSION.cdb_path}'."
    SESSION.target_desc = f"attached to PID {pid}"
    return _section("ATTACHED", SESSION.target_desc) + "\n\n" + _section("CDB BANNER", banner) + "\n\n" + tool_status()


def tool_open_dump(path: str) -> str:
    if SESSION.is_running():
        return "ERROR: a session is already active."
    if not os.path.isfile(path):
        return f"ERROR: dump file not found: {path}"
    try:
        banner = SESSION.open_dump(path)
    except FileNotFoundError:
        return f"ERROR: cdb not found at '{SESSION.cdb_path}'."
    SESSION.target_desc = f"dump: {path}"
    return _section("OPENED DUMP", path) + "\n\n" + _section("CDB BANNER", banner) + "\n\n" + tool_status()


def tool_stop() -> str:
    msg = SESSION.stop()
    return f"### STOPPED\n{msg}"


def tool_break_in() -> str:
    err = _need_session()
    if err:
        return err
    msg = SESSION.break_in()
    time.sleep(0.5)
    pending, saw_prompt, process_exited, _, _ = SESSION.wait_for_event(timeout=10, max_lines=2000, quiet_timeout=1.0)
    if not process_exited:
        SESSION.clear_async_state()
    if not process_exited:
        marker = SESSION.run(".echo broken", timeout=10)
        drained = (pending + "\n" + marker).strip()
    else:
        drained = pending or _async_state_suffix(saw_prompt, process_exited, 10)
    return _section("BREAK", msg) + "\n\n" + _section("STATE", drained)


def tool_status() -> str:
    if not SESSION.is_running():
        return "### STATUS\nno active session"
    parts: list[str] = [f"target = {SESSION.target_desc or 'unknown'}"]
    parts.append(f"cdb = {SESSION.cdb_path}")
    # current process/thread/IP — `.` shows current instruction; `r` first line has rip.
    regs_out = SESSION.run("r", timeout=10)
    regs = parse_registers(regs_out)
    rip = regs.get("rip") or regs.get("eip")
    if rip:
        parts.append(f"rip = {rip}")
    # ln @rip → symbol nearest current IP
    sym = SESSION.run("ln @$ip", timeout=10).strip()
    if sym:
        # take first non-empty informative line
        for line in sym.splitlines():
            if "(" in line or "|" in line:
                parts.append(f"location = {line.strip()}")
                break
    proc = SESSION.run("|", timeout=10)
    thread = SESSION.run("~.", timeout=10)
    return (
        _section("STATUS", "\n".join(parts))
        + "\n\n"
        + _section("PROCESS", proc)
        + "\n\n"
        + _section("CURRENT THREAD", thread)
    )


def tool_io_status() -> str:
    running = SESSION.is_running()
    pairs = [
        ("session_running", str(running)),
        ("target", SESSION.target_desc or "unknown"),
        ("cdb", SESSION.cdb_path),
        ("buffered_lines", str(SESSION.out_q.qsize())),
        ("async_command", SESSION.async_command or "(none)"),
    ]
    if SESSION.async_started_at is not None:
        pairs.append(("async_age_sec", f"{time.time() - SESSION.async_started_at:.1f}"))
    if SESSION.proc is not None:
        pairs.append(("cdb_pid", str(SESSION.proc.pid)))
        poll = SESSION.proc.poll()
        pairs.append(("cdb_exit_code", "(running)" if poll is None else str(poll)))
    return _section("WINDBG MCP I/O STATUS", _kv_block(pairs))


def tool_run_command(
    command: str,
    timeout: float = 60.0,
    filter_pattern: str | None = None,
    max_lines: int | None = None,
    split_commands: bool = False,
    per_command_timeout: float | None = None,
    exclude_pattern: str | None = None,
    ignore_case: bool = False,
    invert_match: bool = False,
    context_before: int = 0,
    context_after: int = 0,
    tail_lines: int | None = None,
) -> str:
    err = _need_session()
    if err:
        return err
    if split_commands:
        commands = _split_cdb_commands(command)
        if not commands:
            return _section(f"CMD: {command}", "(empty)")
        parts: list[str] = []
        each_timeout = per_command_timeout if per_command_timeout is not None else timeout
        for item in commands:
            item_out = SESSION.run(item, timeout=each_timeout)
            item_out = _filter_output(
                item_out,
                filter_pattern=filter_pattern,
                max_lines=max_lines,
                exclude_pattern=exclude_pattern,
                ignore_case=ignore_case,
                invert_match=invert_match,
                context_before=context_before,
                context_after=context_after,
                tail_lines=tail_lines,
            )
            parts.append(_section(f"CMD: {item}", item_out))
        return "\n\n".join(parts)
    out = SESSION.run(command, timeout=timeout)
    out = _filter_output(
        out,
        filter_pattern=filter_pattern,
        max_lines=max_lines,
        exclude_pattern=exclude_pattern,
        ignore_case=ignore_case,
        invert_match=invert_match,
        context_before=context_before,
        context_after=context_after,
        tail_lines=tail_lines,
    )
    return _section(f"CMD: {command}", out)


def _async_state_suffix(
    saw_prompt: bool,
    process_exited: bool,
    timeout: float | None = None,
    quiet_after_output: bool = False,
    saw_exception: bool = False,
) -> str:
    if process_exited:
        return "process exited"
    if saw_prompt:
        return "event/prompt reached"
    if saw_exception:
        return "exception/event detected; no break-in sent"
    if quiet_after_output:
        return "output received and quiet; no break-in sent; async command may still be active"
    if timeout is not None:
        return f"timeout after {int(timeout)}s; no break-in sent, target is still running"
    return "no prompt yet; target may still be running"


def tool_run_command_async(command: str) -> str:
    err = _need_session()
    if err:
        return err
    msg = SESSION.run_async(command)
    return _section("ASYNC COMMAND", msg)


def tool_wait_exception_profile(
    timeout: float = 300.0,
    profile: str = "tg",
    max_lines: int = 2000,
    tail_lines: int | None = 120,
) -> str:
    patterns = {
        "default": r"exception|access violation|c0000005|c0000374|heap corruption|failfast|fatal",
        "tg": r"exception|access violation|c0000005|c0000374|heap corruption|failfast|fatal|Telegram|TG|tgcalls",
        "asan": r"AddressSanitizer|ERROR: AddressSanitizer|heap-use-after-free|stack-use-after-return|buffer-overflow|SUMMARY:",
    }
    exclude = {
        "tg": r"^ModLoad:|Wldp\.dll|The object was not found|Mapping .*regions",
        "default": r"^ModLoad:|Mapping .*regions",
        "asan": r"^ModLoad:|Mapping .*regions",
    }.get(profile, r"^ModLoad:")
    return tool_wait_for_event(
        timeout=timeout,
        max_lines=max_lines,
        quiet_timeout=1.0,
        stop_on_exception=True,
        filter_pattern=patterns.get(profile, patterns["default"]),
        exclude_pattern=exclude,
        ignore_case=True,
        context_before=4,
        context_after=12,
        tail_lines=tail_lines,
    )


def tool_continue_async() -> str:
    err = _need_session()
    if err:
        return err
    msg = SESSION.run_async("g")
    return _section("CONTINUE ASYNC (g)", msg)


def tool_go(
    timeout: float = 120.0,
    max_lines: int = 2000,
    quiet_timeout: float = 1.0,
    stop_on_exception: bool = True,
    filter_pattern: str | None = None,
    exclude_pattern: str | None = None,
    ignore_case: bool = False,
    invert_match: bool = False,
    context_before: int = 0,
    context_after: int = 0,
    tail_lines: int | None = None,
) -> str:
    err = _need_session()
    if err:
        return err
    start = SESSION.run_async("g")
    event = tool_wait_for_event(
        timeout=timeout,
        max_lines=max_lines,
        quiet_timeout=quiet_timeout,
        stop_on_exception=stop_on_exception,
        filter_pattern=filter_pattern,
        exclude_pattern=exclude_pattern,
        ignore_case=ignore_case,
        invert_match=invert_match,
        context_before=context_before,
        context_after=context_after,
        tail_lines=tail_lines,
    )
    return _section("GO (g)", start) + "\n\n" + event


def tool_read_output(
    lines: int = 50,
    filter_pattern: str | None = None,
    exclude_pattern: str | None = None,
    ignore_case: bool = False,
    invert_match: bool = False,
    context_before: int = 0,
    context_after: int = 0,
    tail_lines: int | None = None,
) -> str:
    err = _need_session()
    if err:
        return err
    out, saw_prompt, process_exited = SESSION.read_output(max_lines=int(lines))
    out = _filter_output(
        out,
        filter_pattern=filter_pattern,
        exclude_pattern=exclude_pattern,
        ignore_case=ignore_case,
        invert_match=invert_match,
        context_before=context_before,
        context_after=context_after,
        tail_lines=tail_lines,
    )
    state = _async_state_suffix(saw_prompt, process_exited)
    return _section("OUTPUT", out) + "\n\n" + _section("STATE", state)


def tool_wait_for_event(
    timeout: float = 120.0,
    max_lines: int = 2000,
    quiet_timeout: float = 1.0,
    stop_on_exception: bool = False,
    filter_pattern: str | None = None,
    exclude_pattern: str | None = None,
    ignore_case: bool = False,
    invert_match: bool = False,
    context_before: int = 0,
    context_after: int = 0,
    tail_lines: int | None = None,
) -> str:
    err = _need_session()
    if err:
        return err
    out, saw_prompt, process_exited, quiet_after_output, saw_exception = SESSION.wait_for_event(
        timeout=timeout,
        max_lines=int(max_lines),
        quiet_timeout=quiet_timeout,
        stop_on_exception=stop_on_exception,
    )
    state = _async_state_suffix(
        saw_prompt,
        process_exited,
        timeout if not saw_prompt and not process_exited and not quiet_after_output and not saw_exception else None,
        quiet_after_output,
        saw_exception,
    )
    out = _filter_output(
        out,
        filter_pattern=filter_pattern,
        exclude_pattern=exclude_pattern,
        ignore_case=ignore_case,
        invert_match=invert_match,
        context_before=context_before,
        context_after=context_after,
        tail_lines=tail_lines,
    )
    return _section("EVENT OUTPUT", out) + "\n\n" + _section("STATE", state)


# ----- execution control ----------------------------------------------------


def tool_continue(timeout: float = 120.0) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("g", timeout=timeout)
    return _section("CONTINUE (g)", out) + "\n\n" + tool_status()


def tool_step_in() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("t", timeout=30)
    return _section("STEP IN (t)", out) + "\n\n" + tool_status()


def tool_step_over() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("p", timeout=30)
    return _section("STEP OVER (p)", out) + "\n\n" + tool_status()


def tool_step_out() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("gu", timeout=60)
    return _section("STEP OUT (gu)", out) + "\n\n" + tool_status()


def tool_run_to(address: str, timeout: float = 120.0) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"g {address}", timeout=timeout)
    return _section(f"RUN TO {address}", out) + "\n\n" + tool_status()


# ----- breakpoints ----------------------------------------------------------


def tool_set_breakpoint(location: str, condition: str | None = None) -> str:
    err = _need_session()
    if err:
        return err
    cmd = f"bp {location}"
    rewritten_note = ""
    if condition:
        condition, changed = _rewrite_signed_negative_condition(condition)
        if changed:
            rewritten_note = f"\n\n" + _section("CONDITION REWRITE", condition)
        cmd = f"bp {location} {_cdb_bp_quote(f'.if ({condition}) {{}} .else {{gc}}')}"
    out = SESSION.run(cmd, timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return _section(f"SET BREAKPOINT @ {location}", out or "(ok)") + rewritten_note + "\n\n" + _section("BREAKPOINTS", bl)


def tool_set_conditional_bp(
    location: str,
    condition: str | None = None,
    print_expr: str | None = None,
    continue_if_false: bool = True,
    stop_if: str | None = None,
) -> str:
    err = _need_session()
    if err:
        return err

    effective_condition = stop_if or condition
    condition_rewrite = ""
    if effective_condition:
        effective_condition, changed = _rewrite_signed_negative_condition(effective_condition)
        if changed:
            condition_rewrite = _section("CONDITION REWRITE", effective_condition)
    actions: list[str] = []
    if print_expr:
        actions.append(_bp_printf(f"BP {location}", print_expr))
    action_body = "; ".join(actions)

    if effective_condition:
        true_body = action_body or ".echo conditional breakpoint hit"
        false_body = "gc" if continue_if_false else ".echo conditional breakpoint false"
        bp_commands = f".if ({effective_condition}) {{{true_body}}} .else {{{false_body}}}"
    else:
        bp_commands = action_body

    cmd = f"bp {location}"
    if bp_commands:
        cmd += f" {_cdb_bp_quote(bp_commands)}"
    out = SESSION.run(cmd, timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return (
        _section(f"SET CONDITIONAL BP @ {location}", out or "(ok)")
        + "\n\n"
        + ((condition_rewrite + "\n\n") if condition_rewrite else "")
        + _section("COMMAND", cmd)
        + "\n\n"
        + _section("BREAKPOINTS", bl)
    )


def tool_bp_template(
    location: str,
    template: str = "log_this",
    expr: str | None = None,
    stop_if: str | None = None,
    stack: int = 5,
) -> str:
    err = _need_session()
    if err:
        return err
    actions: list[str] = []
    condition_rewrite = ""
    condition = stop_if
    if condition:
        condition, changed = _rewrite_signed_negative_condition(condition)
        if changed:
            condition_rewrite = _section("CONDITION REWRITE", condition)

    if template == "log_this":
        actions.extend([
            f'.printf "BP {location}: this=%p rcx=%p rdx=%p r8=%p r9=%p rip=%p\\n", @rcx, @rcx, @rdx, @r8, @r9, @rip',
            f"kb {stack}",
            "gc",
        ])
    elif template == "log_expr":
        if not expr:
            return "ERROR: template=log_expr requires expr"
        actions.extend([_bp_printf(f"BP {location}", expr), f"kb {stack}", "gc"])
    elif template == "stop_signed_negative":
        if not expr:
            return "ERROR: template=stop_signed_negative requires expr, e.g. '@rdx'"
        condition, _ = _rewrite_signed_negative_condition(f"{expr} < 0")
        condition_rewrite = _section("CONDITION REWRITE", condition)
        actions.extend([_bp_printf(f"BP {location}", expr), f"kb {stack}"])
    elif template == "stop_pointer_range":
        if not expr or not stop_if:
            return "ERROR: template=stop_pointer_range requires expr and stop_if condition, e.g. expr='@rcx', stop_if='@rcx >= 0x1000 && @rcx < 0x2000'"
        actions.extend([_bp_printf(f"BP {location}", expr), f"kb {stack}"])
    elif template == "log_stack":
        actions.extend([f'.printf "BP {location}: rip=%p\\n", @rip', f"kb {stack}", "gc"])
    else:
        return "ERROR: template must be one of log_this, log_expr, stop_signed_negative, stop_pointer_range, log_stack"

    body = "; ".join(actions)
    if condition:
        body = f".if ({condition}) {{{body}}} .else {{gc}}"
    cmd = f"bp {location} {_cdb_bp_quote(body)}"
    out = SESSION.run(cmd, timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return (
        _section(f"BP TEMPLATE {template} @ {location}", out or "(ok)")
        + "\n\n"
        + ((condition_rewrite + "\n\n") if condition_rewrite else "")
        + _section("COMMAND", cmd)
        + "\n\n"
        + _section("BREAKPOINTS", bl)
    )


def tool_watch_memory(address: str, size: str = "8", access: str = "w", log_stack: bool = True) -> str:
    err = _need_session()
    if err:
        return err
    if access not in {"r", "w", "e"}:
        return "ERROR: access must be one of r (read), w (write), e (execute)"
    if size not in {"1", "2", "4", "8"}:
        return "ERROR: size must be 1, 2, 4 or 8"

    actions = [
        f'.printf "WATCH {access}{size} {address}: ip=%p value=%p\\n", @rip, poi({address})',
        f"dq {address} L1",
    ]
    if log_stack:
        actions.append("kb 5")
    actions.append("gc")
    cmd = f"ba {access}{size} {address} {_cdb_bp_quote('; '.join(actions))}"
    out = SESSION.run(cmd, timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return (
        _section(f"WATCH MEMORY {access}{size} @ {address}", out or "(ok)")
        + "\n\n"
        + _section("COMMAND", cmd)
        + "\n\n"
        + _section("BREAKPOINTS", bl)
    )


def tool_set_data_breakpoint(size: str, access: str, address: str) -> str:
    err = _need_session()
    if err:
        return err
    if access not in {"r", "w", "e"}:
        return "ERROR: access must be one of r (read), w (write), e (execute)"
    if size not in {"1", "2", "4", "8"}:
        return "ERROR: size must be 1, 2, 4 or 8"
    out = SESSION.run(f"ba {access}{size} {address}", timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return _section(f"DATA BP {access}{size} @ {address}", out or "(ok)") + "\n\n" + _section("BREAKPOINTS", bl)


def tool_list_breakpoints() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("bl", timeout=10)
    return _section("BREAKPOINTS", out or "(none)")


def tool_save_breakpoints(name: str) -> str:
    err = _need_session()
    if err:
        return err
    safe = _safe_name(name)
    path = os.path.join(_breakpoint_store_dir(), f"{safe}.cmd")
    out = SESSION.run(".bpcmds", timeout=10)
    commands = []
    for line in out.splitlines():
        command = _strip_prompt_prefix(line).rstrip()
        if command:
            commands.append(command)
    if not commands:
        return _section("SAVE BREAKPOINTS", "No breakpoint commands returned by .bpcmds")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(commands) + "\n")
    return _section("SAVE BREAKPOINTS", f"saved {len(commands)} command(s) to {path}") + "\n\n" + _section("COMMANDS", "\n".join(commands))


def tool_load_breakpoints(name: str, clear_existing: bool = False) -> str:
    err = _need_session()
    if err:
        return err
    safe = _safe_name(name)
    path = os.path.join(_breakpoint_store_dir(), f"{safe}.cmd")
    if not os.path.isfile(path):
        return f"ERROR: saved breakpoint set not found: {path}"
    with open(path, "r", encoding="utf-8") as f:
        commands = [
            _strip_prompt_prefix(line)
            for line in f
            if line.strip() and not line.lstrip().startswith("$$")
        ]
    parts: list[str] = []
    if clear_existing:
        parts.append(_section("CLEAR EXISTING", SESSION.run("bc *", timeout=10) or "(ok)"))
    for command in commands:
        parts.append(_section(f"LOAD: {command}", SESSION.run(command, timeout=10) or "(ok)"))
    parts.append(_section("BREAKPOINTS", SESSION.run("bl", timeout=10) or "(none)"))
    return "\n\n".join(parts)


def tool_clear_breakpoint(spec: str = "*") -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"bc {spec}", timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return _section(f"CLEAR BP {spec}", out or "(ok)") + "\n\n" + _section("BREAKPOINTS", bl)


def tool_disable_breakpoint(spec: str) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"bd {spec}", timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return _section(f"DISABLE BP {spec}", out or "(ok)") + "\n\n" + _section("BREAKPOINTS", bl)


def tool_enable_breakpoint(spec: str) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"be {spec}", timeout=10)
    bl = SESSION.run("bl", timeout=10)
    return _section(f"ENABLE BP {spec}", out or "(ok)") + "\n\n" + _section("BREAKPOINTS", bl)


# ----- registers / expressions ---------------------------------------------


def tool_registers(group: str = "default") -> str:
    err = _need_session()
    if err:
        return err
    cmd = "r"
    if group == "fp":
        cmd = "rF"
    elif group == "xmm":
        cmd = "rXMM"
    elif group == "all":
        cmd = "rM 0x40"
    raw = SESSION.run(cmd, timeout=10)
    regs = parse_registers(raw)
    pretty = _kv_block([(k, v) for k, v in regs.items()]) if regs else "(failed to parse)"
    return _section("REGISTERS", pretty) + "\n\n" + _section("RAW", raw)


def tool_set_register(name: str, value: str) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"r @{name} = {value}", timeout=10)
    new = SESSION.run(f"r @{name}", timeout=10)
    return _section(f"SET {name}={value}", out or "(ok)") + "\n\n" + _section("NOW", new)


def tool_evaluate(expression: str) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"? {expression}", timeout=10)
    return _section(f"EVAL: {expression}", out)


# ----- stack / disasm / memory ---------------------------------------------


def tool_call_stack(count: int = 30, mode: str = "default") -> str:
    err = _need_session()
    if err:
        return err
    cmd = "k"
    if mode == "params":
        cmd = "kP"
    elif mode == "frames":
        cmd = "kf"
    elif mode == "verbose":
        cmd = "kv"
    out = SESSION.run(f"{cmd} {count}", timeout=15)
    return _section(f"CALL STACK ({mode}, top {count})", out)


def tool_stack_find_thread(
    pattern: str | None = None,
    sp: str | None = None,
    count: int = 20,
    mode: str = "params",
    context_before: int = 2,
    context_after: int = 8,
    switch: bool = False,
) -> str:
    err = _need_session()
    if err:
        return err
    cmd = "kP" if mode == "params" else "kv" if mode == "verbose" else "kf" if mode == "frames" else "k"
    raw = SESSION.run(f"~* {cmd} {count}", timeout=60)
    search = pattern or sp
    filtered = raw
    if search:
        filtered = _filter_output(
            raw,
            filter_pattern=re.escape(search) if sp else search,
            ignore_case=True,
            context_before=context_before,
            context_after=context_after,
        )
    tid = None
    if switch and search:
        idx = -1
        lines = raw.splitlines()
        match_re = re.compile(re.escape(search) if sp else search, re.IGNORECASE)
        for i, line in enumerate(lines):
            if match_re.search(line):
                idx = i
                break
        if idx >= 0:
            for j in range(idx, -1, -1):
                m = re.search(r"\bId:\s*[0-9a-fA-F]+\.([0-9a-fA-F]+)\b", lines[j])
                if m:
                    tid = m.group(1)
                    break
    parts = [_section("THREAD STACK MATCHES", filtered or "(no matches)")]
    if switch and tid:
        parts.append(tool_switch_thread_by_tid(tid))
    elif switch:
        parts.append(_section("SWITCH", "No TID found near match"))
    return "\n\n".join(parts)


def tool_shadow_stack(count: int = 32, address: str = "@ssp") -> str:
    err = _need_session()
    if err:
        return err
    ssp_raw, ssp = _read_ssp()
    regs = "\n".join([SESSION.run("r @rsp", timeout=10), ssp_raw])
    if address == "@ssp" and not ssp:
        return (
            _section("STACK POINTERS", regs)
            + "\n\n"
            + _section("SHADOW STACK", "ssp is 0 or unavailable in the current context; not dumping @ssp")
        )
    stack = SESSION.run(f"dps {address} L{count:x}", timeout=15)
    return _section("STACK POINTERS", regs) + "\n\n" + _section(f"SHADOW STACK dps {address} L{count:x}", stack)


def tool_shadow_stack_compare(count: int = 32) -> str:
    err = _need_session()
    if err:
        return err
    ssp_raw, ssp = _read_ssp()
    normal_raw = SESSION.run(f"dps @rsp L{count:x}", timeout=15)
    if not ssp:
        return (
            _section("SSP", ssp_raw)
            + "\n\n"
            + _section("NORMAL RAW", normal_raw)
            + "\n\n"
            + _section("SHADOW STACK", "ssp is 0 or unavailable in the current context; compare skipped")
        )
    shadow_raw = SESSION.run(f"dps @ssp L{count:x}", timeout=15)
    normal = _parse_dps_rows(normal_raw)
    shadow = _parse_dps_rows(shadow_raw)
    rows = ["idx | normal_stack_value | shadow_stack_value | match | normal_symbol | shadow_symbol"]
    for i in range(max(len(normal), len(shadow))):
        n = normal[i] if i < len(normal) else ("?", "?", "")
        s = shadow[i] if i < len(shadow) else ("?", "?", "")
        rows.append(f"{i:03d} | {n[1]} | {s[1]} | {'==' if n[1] == s[1] else '!='} | {n[2]} | {s[2]}")
    return (
        _section("STACK VS SHADOW STACK", "\n".join(rows))
        + "\n\n"
        + _section("NORMAL RAW", normal_raw)
        + "\n\n"
        + _section("SHADOW RAW", shadow_raw)
    )


def tool_shadow_stack_return(index: int = 0, disasm_count: int = 8) -> str:
    err = _need_session()
    if err:
        return err
    ssp_raw, ssp = _read_ssp()
    if not ssp:
        return _section("SSP", ssp_raw) + "\n\n" + _section("SHADOW RETURN", "ssp is 0 or unavailable in the current context")
    slot = _shadow_slot_expr(index)
    value = SESSION.run(f"dps {slot} L1", timeout=10)
    sym = SESSION.run(f"ln poi({slot})", timeout=10)
    dis = SESSION.run(f"u poi({slot}) L{disasm_count:x}", timeout=10)
    return (
        _section(f"SHADOW RETURN SLOT {index} ({slot})", value)
        + "\n\n"
        + _section("SYMBOL", sym)
        + "\n\n"
        + _section("DISASM", dis)
    )


def tool_run_to_shadow_return(index: int = 0, async_run: bool = True, timeout: float = 120.0) -> str:
    err = _need_session()
    if err:
        return err
    ssp_raw, ssp = _read_ssp()
    if not ssp:
        return _section("SSP", ssp_raw) + "\n\n" + _section("RUN TO SHADOW RETURN", "ERROR: ssp is 0 or unavailable in the current context")
    slot = _shadow_slot_expr(index)
    target = f"poi({slot})"
    if async_run:
        msg = SESSION.run_async(f"g {target}")
        return _section(f"RUN TO SHADOW RETURN {index}", msg + f"\ntarget = {target}")
    out = SESSION.run(f"g {target}", timeout=timeout)
    return _section(f"RUN TO SHADOW RETURN {index}", out) + "\n\n" + tool_status()


def tool_disassemble(address: str = ".", count: int = 16, function: bool = False) -> str:
    err = _need_session()
    if err:
        return err
    if function:
        out = SESSION.run(f"uf {address}", timeout=20)
        title = f"DISASSEMBLE FUNCTION @ {address}"
    else:
        out = SESSION.run(f"u {address} L{count:x}", timeout=10)
        title = f"DISASSEMBLE @ {address} ({count} insns)"
    return _section(title, out)


def tool_disassemble_back(address: str = ".", count: int = 8) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"ub {address} L{count:x}", timeout=10)
    return _section(f"DISASSEMBLE BACK @ {address} ({count} insns)", out)


_MEM_FORMATS = {
    "byte": "db",
    "word": "dw",
    "dword": "dd",
    "qword": "dq",
    "ascii": "da",
    "unicode": "du",
    "pointer": "dp",
}


def tool_read_memory(address: str, count: int = 32, fmt: str = "byte") -> str:
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address)
    cmd = _MEM_FORMATS.get(fmt)
    if not cmd:
        return f"ERROR: unknown fmt '{fmt}'. Choose one of: {', '.join(_MEM_FORMATS)}"
    out = SESSION.run(f"{cmd} {address} L{count:x}", timeout=15)
    return _section(f"MEMORY [{fmt}] @ {address} ({count} units)", out)


_WRITE_FORMATS = {"byte": "eb", "word": "ew", "dword": "ed", "qword": "eq", "ascii": "ea", "unicode": "eu"}


def tool_write_memory(address: str, values: str, fmt: str = "byte") -> str:
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address)
    cmd = _WRITE_FORMATS.get(fmt)
    if not cmd:
        return f"ERROR: unknown fmt '{fmt}'. Choose one of: {', '.join(_WRITE_FORMATS)}"
    out = SESSION.run(f"{cmd} {address} {values}", timeout=10)
    return _section(f"WRITE [{fmt}] @ {address}", out or "(ok)")


def tool_search_memory(start: str, length: str, pattern: str, kind: str = "bytes") -> str:
    err = _need_session()
    if err:
        return err
    flag = {"bytes": "-b", "ascii": "-a", "unicode": "-u", "dword": "-d", "qword": "-q"}.get(kind, "-b")
    out = SESSION.run(f"s {flag} {start} L{length} {pattern}", timeout=60)
    return _section(f"SEARCH {kind} for '{pattern}' in [{start}, +{length}]", out or "(no hits)")


# ----- modules / symbols / threads / processes -----------------------------


def tool_list_modules(filter: str = "") -> str:
    err = _need_session()
    if err:
        return err
    cmd = "lm" if not filter else f"lm m {filter}"
    out = SESSION.run(cmd, timeout=20)
    return _section("MODULES", out)


def tool_module_info(name: str) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"lmDvm {name}", timeout=15)
    return _section(f"MODULE {name}", out)


def tool_list_threads() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("~", timeout=10)
    return _section("THREADS", out)


def tool_switch_thread(index: int) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"~{index}s", timeout=10)
    return _section(f"SWITCH THREAD {index}", out or "(ok)") + "\n\n" + tool_status()


def tool_switch_thread_by_tid(tid: str) -> str:
    err = _need_session()
    if err:
        return err
    tid = tid.strip()
    if "." in tid:
        tid = tid.rsplit(".", 1)[1]
    if tid.lower().startswith("0x"):
        tid = tid[2:]
    if not re.fullmatch(r"[0-9a-fA-F]+", tid):
        return "ERROR: tid must be a hex thread id, e.g. '43110' or '0x43110'"
    out = SESSION.run(f"~~[{tid}]s", timeout=10)
    return _section(f"SWITCH THREAD TID {tid}", out or "(ok)") + "\n\n" + tool_status()


def tool_list_processes() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("|", timeout=10)
    return _section("PROCESSES", out)


def tool_find_symbols(pattern: str) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"x {pattern}", timeout=30)
    return _section(f"SYMBOLS matching '{pattern}'", out or "(no matches)")


def tool_address_to_symbol(address: str) -> str:
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address)
    out = SESSION.run(f"ln {address}", timeout=10)
    return _section(f"NEAREST SYMBOL TO {address}", out or "(none)")


def tool_locals() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("dv /V /i /t", timeout=10)
    return _section("LOCALS (dv)", out or "(none — symbols may be missing)")


def tool_source_lines(address: str = ".") -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f".lines -e\nlsa {address}", timeout=10)
    return _section(f"SOURCE @ {address}", out)


# ----- crash / heap / handle / PEB / TEB -----------------------------------


def tool_analyze_crash(verbose: bool = True) -> str:
    err = _need_session()
    if err:
        return err
    cmd = "!analyze -v" if verbose else "!analyze"
    out = SESSION.run(cmd, timeout=120)
    return _section("!analyze", out)


def tool_peb() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("!peb", timeout=15)
    return _section("PEB", out)


def tool_teb() -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run("!teb", timeout=10)
    return _section("TEB", out)


def tool_heap(args: str = "") -> str:
    err = _need_session()
    if err:
        return err
    out = _filter_heap_noise(SESSION.run(f"!heap {args}".strip(), timeout=60))
    return _section(f"!heap {args}".strip(), out)


def tool_handle(args: str = "") -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f"!handle {args}".strip(), timeout=30)
    return _section(f"!handle {args}".strip(), out)


def tool_address(address: str = "", timeout: float = 30.0, max_lines: int | None = None) -> str:
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address) if address else address
    out = SESSION.run(f"!address {address}".strip(), timeout=timeout)
    out = _filter_address_noise(out, max_lines=max_lines)
    return _section(f"!address {address}".strip(), out)


def tool_dt(type_name: str, address: str | None = None) -> str:
    err = _need_session()
    if err:
        return err
    cmd = f"dt {type_name}" + (f" {address}" if address else "")
    out = SESSION.run(cmd, timeout=20)
    return _section(cmd, out)


# ----- symbol / source paths -----------------------------------------------


def tool_set_symbol_path(path: str) -> str:
    err = _need_session()
    if err:
        return err
    SESSION.symbol_path = path
    out = SESSION.run(f".sympath {path}", timeout=10)
    reload_out = SESSION.run(".reload", timeout=120)
    return _section("SET SYMBOL PATH", out) + "\n\n" + _section("RELOAD", reload_out)


def tool_reload_symbols(force: bool = False) -> str:
    err = _need_session()
    if err:
        return err
    cmd = ".reload /f" if force else ".reload"
    out = SESSION.run(cmd, timeout=120)
    return _section("RELOAD SYMBOLS", out)


def tool_set_source_path(path: str) -> str:
    err = _need_session()
    if err:
        return err
    out = SESSION.run(f".srcpath {path}", timeout=10)
    return _section("SET SOURCE PATH", out)


# ---------------------------------------------------------------------------
# EXTRA TOOLS — heap exploit analysis, crash triage, ASAN
# ---------------------------------------------------------------------------

def tool_heap_spray_check() -> str:
    """Check for heap spray patterns — useful for exploit analysis."""
    err = _need_session()
    if err:
        return err
    parts = []
    # Heap summary
    parts.append(_section("HEAP SUMMARY", SESSION.run("!heap -s", timeout=30)))
    # Check for large allocations
    parts.append(_section("HEAP STATS", SESSION.run("!heap -stat", timeout=30)))
    return "\n\n".join(parts)


def tool_crash_triage() -> str:
    """Full crash triage: !analyze + registers + stack + nearby memory."""
    err = _need_session()
    if err:
        return err
    parts = []
    # Quick analyze
    parts.append(_section("ANALYZE", SESSION.run("!analyze -v", timeout=120)))
    # Registers
    regs = SESSION.run("r", timeout=10)
    parts.append(_section("REGISTERS", regs))
    # Call stack
    parts.append(_section("CALL STACK", SESSION.run("kP 20", timeout=15)))
    # Exception record
    parts.append(_section("EXCEPTION", SESSION.run(".exr -1", timeout=10)))
    # Faulting address context
    fault_addr = SESSION.run("? @$exr_addr", timeout=10)
    if "0x" in fault_addr.lower():
        parts.append(_section("FAULT ADDR CONTEXT", SESSION.run(f"!address @$exr_addr", timeout=15)))
    return "\n\n".join(parts)


def tool_asan_parse() -> str:
    """Parse ASAN output from the target's stderr/stdout — useful when running ASAN binaries."""
    err = _need_session()
    if err:
        return err
    # Get last exception info
    parts = []
    parts.append(_section("EXCEPTION RECORD", SESSION.run(".exr -1", timeout=10)))
    parts.append(_section("CONTEXT RECORD", SESSION.run(".cxr -1", timeout=10)))
    parts.append(_section("CALL STACK (exception)", SESSION.run("kP 30", timeout=15)))
    # Check if it's an ASAN abort (SIGABRT = int 3 or STATUS_BREAKPOINT)
    parts.append(_section("LAST EVENT", SESSION.run(".lastevent", timeout=10)))
    return "\n\n".join(parts)


def tool_heap_block_info(address: str) -> str:
    """Inspect a specific heap block — size, flags, neighbors."""
    err = _need_session()
    if err:
        return err
    parts = []
    parts.append(_section(f"HEAP BLOCK @ {address}", _filter_heap_noise(SESSION.run(f"!heap -p -a {address}", timeout=30))))
    parts.append(_section("MEMORY REGION", SESSION.run(f"!address {address}", timeout=15)))
    # Read 64 bytes before and after
    parts.append(_section("MEMORY BEFORE", SESSION.run(f"db {address}-40 L40", timeout=10)))
    parts.append(_section("MEMORY AT", SESSION.run(f"db {address} L80", timeout=10)))
    return "\n\n".join(parts)


def tool_heap_neighbors(address: str, before: int = 0x40, after: int = 0x100) -> str:
    """Inspect bytes and pointer-looking values around a heap block."""
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address)
    total = before + after
    qwords = max(1, (total + 7) // 8)
    start_expr = f"{address}-0x{before:x}"
    parts = [
        _section(f"HEAP BLOCK @ {address}", _filter_heap_noise(SESSION.run(f"!heap -p -a {address}", timeout=30))),
        _section("BYTES AROUND BLOCK", SESSION.run(f"db {start_expr} L0x{total:x}", timeout=10)),
        _section("POINTERS/SYMBOLS AROUND BLOCK", SESSION.run(f"dps {start_expr} L0x{qwords:x}", timeout=10)),
    ]
    return "\n\n".join(parts)


def tool_object_context(
    address: str,
    before: int = 0x40,
    after: int = 0x100,
    span_count: int = 0,
    include_vtable: bool = True,
) -> str:
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address)
    total = before + after
    qwords = max(1, (total + 7) // 8)
    start_expr = f"{address}-0x{before:x}"
    region = _filter_address_noise(SESSION.run(f"!address {address}", timeout=30), max_lines=80)
    parts = [
        _section("ADDRESS", SESSION.run(f"? {address}", timeout=10)),
        _section("NEAREST SYMBOL", SESSION.run(f"ln {address}", timeout=10)),
        _section("MEMORY REGION", region),
        _section("HEAP BLOCK", _filter_heap_noise(SESSION.run(f"!heap -p -a {address}", timeout=30))),
        _section("QWORDS AT OBJECT", SESSION.run(f"dps {address} L20", timeout=10)),
        _section("BYTES AROUND OBJECT", SESSION.run(f"db {start_expr} L0x{total:x}", timeout=10)),
        _section("POINTERS/SYMBOLS AROUND OBJECT", SESSION.run(f"dps {start_expr} L0x{qwords:x}", timeout=10)),
    ]
    if include_vtable and "Usage:                  Stack" not in region:
        parts.append(_section("POTENTIAL VTABLE", tool_find_vtable(address)))
    elif include_vtable:
        parts.append(_section("POTENTIAL VTABLE", "skipped because !address reports Usage: Stack"))
    if span_count > 0:
        parts.append(tool_decode_spans(address, span_count))
    return "\n\n".join(parts)


def tool_find_vtable_owner(
    vtable_addr: str,
    heap_start: str | None = None,
    heap_length: str | None = None,
    max_hits: int = 64,
    max_regions: int = 256,
    region_timeout: float = 20.0,
    require_first_qword: bool = True,
) -> str:
    err = _need_session()
    if err:
        return err

    searches: list[tuple[str, str]] = []
    if heap_start and heap_length:
        searches.append((heap_start, heap_length))
    else:
        address_raw = SESSION.run("!address -f:Heap", timeout=120)
        address_clean = _filter_address_noise(address_raw)
        ranges = _parse_heap_ranges_from_address(address_clean)
        if not ranges:
            fallback_cmd = f'!address -f:Heap -c:"s -q %1 %3 {vtable_addr}"'
            raw = SESSION.run(fallback_cmd, timeout=120)
            hits = _parse_address_hits(raw, max_hits=max_hits)
            parts = [
                _section("HEAP RANGE DISCOVERY", "Could not parse heap ranges from !address -f:Heap; used legacy -c fallback."),
                _section("SEARCH", fallback_cmd),
                _section("RAW HITS", raw or "(no hits)"),
            ]
            if not hits:
                parts.append(_section("OWNERS", "No object candidates found. Pass heap_start and heap_length explicitly."))
                return "\n\n".join(parts)
            rows = ["hit_address | user_ptr | offset | user_size | heap_block_summary"]
            for hit in hits:
                heap_info = _filter_heap_noise(SESSION.run(f"!heap -p -a {hit}", timeout=20))
                user_ptr, user_size = _parse_heap_user_block(heap_info)
                offset = _parse_cdb_int(hit) - user_ptr if user_ptr is not None else None
                if require_first_qword and offset not in (0, None):
                    continue
                summary = next((line.strip() for line in heap_info.splitlines() if line.strip()), "(no heap info)")
                rows.append(
                    f"{hit} | "
                    f"{_format_cdb_hex(user_ptr) if user_ptr is not None else '?'} | "
                    f"{offset if offset is not None else '?'} | "
                    f"{hex(user_size) if user_size is not None else '?'} | "
                    f"{summary}"
                )
            candidate_count = len(rows) - 1
            if candidate_count == 0 and require_first_qword:
                rows.append("(all hits were inside heap blocks at non-zero offset)")
            parts.append(_section(f"OWNER CANDIDATES ({candidate_count})", "\n".join(rows)))
            return "\n\n".join(parts)
        for start, length in ranges[:max_regions]:
            searches.append((_format_cdb_hex(start), f"0x{length:x}"))

    raw_parts: list[str] = []
    hits: list[str] = []
    searched = 0
    for start, length in searches:
        if len(hits) >= max_hits:
            break
        search_cmd = f"s -q {start} L{length} {vtable_addr}"
        raw = SESSION.run(search_cmd, timeout=region_timeout)
        searched += 1
        raw_parts.append(f"$ {search_cmd}\n{raw}".strip())
        for hit in _parse_address_hits(raw, max_hits=max_hits - len(hits)):
            if hit not in hits:
                hits.append(hit)

    source = (
        f"explicit range {heap_start} L{heap_length}"
        if heap_start and heap_length
        else f"{len(searches)} heap range(s) parsed from !address -f:Heap; searched {searched}"
    )
    parts = [
        _section("RANGE SOURCE", source),
        _section("RAW HITS", "\n\n".join(raw_parts) or "(no hits)"),
    ]
    if not hits:
        parts.append(_section("OWNERS", "No object candidates found."))
        return "\n\n".join(parts)

    rows = ["hit_address | user_ptr | offset | user_size | heap_block_summary"]
    for hit in hits:
        heap_info = _filter_heap_noise(SESSION.run(f"!heap -p -a {hit}", timeout=20))
        user_ptr, user_size = _parse_heap_user_block(heap_info)
        offset = _parse_cdb_int(hit) - user_ptr if user_ptr is not None else None
        if require_first_qword and offset not in (0, None):
            continue
        summary = next((line.strip() for line in heap_info.splitlines() if line.strip()), "(no heap info)")
        rows.append(
            f"{hit} | "
            f"{_format_cdb_hex(user_ptr) if user_ptr is not None else '?'} | "
            f"{offset if offset is not None else '?'} | "
            f"{hex(user_size) if user_size is not None else '?'} | "
            f"{summary}"
        )
    candidate_count = len(rows) - 1
    if candidate_count == 0 and require_first_qword:
        rows.append("(all hits were inside heap blocks at non-zero offset)")
    parts.append(_section(f"OWNER CANDIDATES ({candidate_count})", "\n".join(rows)))
    return "\n\n".join(parts)


def tool_decode_spans(address: str, count: int = 16) -> str:
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address)
    if count <= 0:
        return "ERROR: count must be positive"
    byte_count = count * 8
    raw = SESSION.run(f"db {address} L0x{byte_count:x}", timeout=15)
    data = _parse_db_bytes(raw)
    if len(data) < byte_count:
        return (
            _section("DECODE SPANS", f"ERROR: read {len(data)} byte(s), expected {byte_count}")
            + "\n\n"
            + _section("RAW", raw)
        )

    rows = ["idx | address | x | y | len | cov | raw7"]
    base_eval = SESSION.run(f"? {address}", timeout=10)
    base_match = re.search(r"Evaluate expression:\s*([0-9]+)\s*=\s*([0-9a-fA-F`]+)", base_eval)
    base_int = int(base_match.group(1)) if base_match else None
    for i in range(count):
        chunk = data[i * 8 : i * 8 + 8]
        x = int.from_bytes(chunk[0:2], "little", signed=True)
        y = int.from_bytes(chunk[2:4], "little", signed=True)
        length = int.from_bytes(chunk[4:6], "little", signed=False)
        cov = chunk[6]
        raw7 = chunk[7]
        item_addr = f"0x{base_int + i * 8:x}" if base_int is not None else f"{address}+0x{i * 8:x}"
        rows.append(f"{i:03d} | {item_addr} | {x} | {y} | {length} | {cov} | 0x{raw7:02x}")
    return _section(f"VRle::Span[{count}] @ {address}", "\n".join(rows)) + "\n\n" + _section("RAW", raw)


def tool_find_vtable(address: str) -> str:
    """Check if address looks like a vtable pointer and resolve it."""
    err = _need_session()
    if err:
        return err
    address = _normalize_cdb_expr(address)
    parts = []
    # Read pointer at address
    ptr = SESSION.run(f"dq {address} L1", timeout=10)
    parts.append(_section(f"POINTER @ {address}", ptr))
    # Try to resolve as symbol
    sym = SESSION.run(f"ln poi({address})", timeout=10)
    parts.append(_section("SYMBOL", sym))
    # Disassemble what it points to
    dis = SESSION.run(f"u poi({address}) L8", timeout=10)
    parts.append(_section("DISASM @ *ptr", dis))
    return "\n\n".join(parts)


def tool_thread_stacks() -> str:
    """Show call stacks for ALL threads — useful for race condition analysis."""
    err = _need_session()
    if err:
        return err
    out = SESSION.run("~* kP 15", timeout=60)
    return _section("ALL THREAD STACKS", out)


def tool_exception_chain() -> str:
    """Show full exception chain and context."""
    err = _need_session()
    if err:
        return err
    parts = []
    parts.append(_section("LAST EVENT", SESSION.run(".lastevent", timeout=10)))
    parts.append(_section("EXCEPTION RECORD", SESSION.run(".exr -1", timeout=10)))
    parts.append(_section("EXCEPTION CONTEXT", SESSION.run(".cxr -1", timeout=10)))
    parts.append(_section("STACK AT EXCEPTION", SESSION.run("kP 20", timeout=15)))
    parts.append(_section("SEH CHAIN", SESSION.run("!exchain", timeout=10)))
    return "\n\n".join(parts)


_HELP_TEXT = """\
WinDbg MCP — quick orientation for the model.

TYPICAL FLOW
  1. windbg_start_executable | windbg_attach | windbg_open_dump
  2. windbg_status                          # see RIP / nearest symbol / thread
  3. windbg_set_breakpoint location=...     # before continuing
  4. windbg_go                              # safe g + wait, no break-in timeout
  5. windbg_call_stack / windbg_registers / windbg_disassemble
  6. windbg_step_over | step_in | step_out  # single-step
  7. windbg_stop                            # quit cdb

KEY CONCEPTS
  - ALL inspection tools require an active session. Without one they return
    a clear ERROR. Always call windbg_status if you are unsure.
  - Each step / continue auto-appends a fresh STATUS section so you do not
    need to re-query state after every move.
  - For anything not covered by a dedicated tool, use windbg_run_command
    with a raw cdb command. Examples:
      .frame 3                  # switch to stack frame 3
      !exchain                  # SEH chain
      !cppexr <addr>            # decode C++ exception record
      !pe                       # show last exception record
      kp                        # call stack with parameter values
  - If a raw command contains multiple cdb commands like `.frame 9; dv /V`,
    call windbg_run_command with split_commands=true so each command gets its
    own prompt/marker wait.
  - Use windbg_switch_thread_by_tid for OS thread IDs from stacks: ~~[tid]s.
  - Filtering supports include/exclude regexes, case-insensitive matching,
    inverted matching, context_before/context_after, max_lines, and tail_lines.
  - For CET/HW shadow stack work, start with windbg_shadow_stack. If @ssp is
    zero in the current context, switch to the relevant thread/frame and try
    again.

CDB EXPRESSIONS
  - Registers in expressions: @rax, @rip, @rsp ...
  - Dereference: poi(addr) for pointer, by(a)/wo(a)/dwo(a)/qwo(a) for sized
  - Hex literals: 0x... or use the cdb default (radix can be set with `n 16`).

ADDRESS / SYMBOL FORMS
  module!Symbol               kernel32!CreateFileW
  module!Symbol+0xNN          mymod!Foo+0x42
  bare 64-bit address          00007ff7`12340000

TIMEOUTS
  - Long-running targets: pass timeout=<seconds> to windbg_continue / run_to.
  - On timeout the server force-breaks cdb so the prompt is recovered;
    output ends with [TIMEOUT ... break-in sent, target paused].
  - If you must not pause the target, use windbg_continue_async followed by
    windbg_wait_for_event or windbg_read_output. Those never send break-in on
    timeout.
  - Prefer windbg_go for normal "continue until something interesting" work.
    It starts g and waits without forcing Ctrl+Break on timeout.
  - For quiet long-running targets, pass stop_on_exception=true to
    windbg_wait_for_event. It ignores quiet output gaps until an exception-like
    event, prompt, process exit, or the absolute timeout.
"""


def tool_help() -> str:
    return _section("WINDBG MCP HELP", _HELP_TEXT)


# ---------------------------------------------------------------------------
# MCP tool registry
# ---------------------------------------------------------------------------


class Tool:
    def __init__(
        self,
        name: str,
        description: str,
        schema: dict[str, Any],
        handler: Callable[..., str],
    ) -> None:
        self.name = name
        self.description = description
        self.schema = schema
        self.handler = handler


def _str(desc: str) -> dict[str, Any]:
    return {"type": "string", "description": desc}


def _int(desc: str, default: int | None = None) -> dict[str, Any]:
    s: dict[str, Any] = {"type": "integer", "description": desc}
    if default is not None:
        s["default"] = default
    return s


def _bool(desc: str, default: bool = False) -> dict[str, Any]:
    return {"type": "boolean", "description": desc, "default": default}


def _enum(desc: str, values: list[str], default: str | None = None) -> dict[str, Any]:
    s: dict[str, Any] = {"type": "string", "description": desc, "enum": values}
    if default:
        s["default"] = default
    return s


TOOLS: list[Tool] = [
    Tool(
        "windbg_help",
        "Show a quick orientation cheatsheet for this MCP: typical workflow, key concepts, address forms, and timeout semantics. Call this first if you are unsure how to drive the debugger.",
        {"type": "object", "properties": {}},
        lambda: tool_help(),
    ),
    Tool(
        "windbg_start_executable",
        "Launch a Windows executable under cdb. The target starts SUSPENDED at the initial breakpoint — use windbg_continue to run it.",
        {
            "type": "object",
            "properties": {
                "exe": _str("Full path to the .exe to launch"),
                "args": {"type": "array", "items": {"type": "string"}, "description": "Command-line arguments"},
            },
            "required": ["exe"],
        },
        lambda exe, args=None: tool_start_executable(exe, args),
    ),
    Tool(
        "windbg_attach",
        "Attach cdb to a running process by PID. The process is paused on attach.",
        {"type": "object", "properties": {"pid": _int("Target process ID")}, "required": ["pid"]},
        lambda pid: tool_attach(int(pid)),
    ),
    Tool(
        "windbg_open_dump",
        "Open a Windows crash dump (.dmp) for post-mortem analysis. Combine with windbg_analyze_crash.",
        {"type": "object", "properties": {"path": _str("Path to .dmp file")}, "required": ["path"]},
        lambda path: tool_open_dump(path),
    ),
    Tool(
        "windbg_stop",
        "Quit the cdb session and release the target.",
        {"type": "object", "properties": {}},
        lambda: tool_stop(),
    ),
    Tool(
        "windbg_status",
        "Show whether a session is active, current target, RIP, nearest symbol, current process and thread.",
        {"type": "object", "properties": {}},
        lambda: tool_status(),
    ),
    Tool(
        "windbg_io_status",
        "Show MCP-side debugger I/O state: active cdb PID, buffered output lines, async command, and async age.",
        {"type": "object", "properties": {}},
        lambda: tool_io_status(),
    ),
    Tool(
        "windbg_break_in",
        "Break into a running target (Ctrl+Break). Use this when the program is executing and you need to pause it.",
        {"type": "object", "properties": {}},
        lambda: tool_break_in(),
    ),
    Tool(
        "windbg_run_command",
        "Run an arbitrary cdb/WinDbg command verbatim. Optional regex filter keeps only matching lines; max_lines caps noisy output.",
        {
            "type": "object",
            "properties": {
                "command": _str("Raw cdb command, e.g. '!process 0 0' or '.frame 3'"),
                "timeout": _int("Seconds to wait for completion", 60),
                "filter_pattern": _str("Optional regex; when set, only matching output lines are returned"),
                "exclude_pattern": _str("Optional regex; matching output lines are removed before include filtering"),
                "ignore_case": _bool("Apply include/exclude regexes case-insensitively", False),
                "invert_match": _bool("With filter_pattern, keep non-matching lines instead of matching lines", False),
                "context_before": _int("Include this many lines before each filter_pattern match", 0),
                "context_after": _int("Include this many lines after each filter_pattern match", 0),
                "max_lines": _int("Optional maximum number of output lines to return"),
                "tail_lines": _int("Return only the last N filtered lines before max_lines is applied"),
                "split_commands": _bool("Split on semicolons outside quotes and run each command separately", False),
                "per_command_timeout": _int("Seconds per split command; defaults to timeout", 60),
            },
            "required": ["command"],
        },
        lambda command, timeout=60, filter_pattern=None, max_lines=None, split_commands=False, per_command_timeout=None,
        exclude_pattern=None, ignore_case=False, invert_match=False, context_before=0, context_after=0,
        tail_lines=None: tool_run_command(
            command,
            float(timeout),
            filter_pattern,
            int(max_lines) if max_lines is not None else None,
            bool(split_commands),
            float(per_command_timeout) if per_command_timeout is not None else None,
            exclude_pattern,
            bool(ignore_case),
            bool(invert_match),
            int(context_before),
            int(context_after),
            int(tail_lines) if tail_lines is not None else None,
        ),
    ),
    Tool(
        "windbg_run_command_async",
        "Send a raw cdb command and return immediately without waiting for a prompt and without break-in. Use windbg_wait_for_event/read_output afterward.",
        {"type": "object", "properties": {"command": _str("Raw cdb command to send")}, "required": ["command"]},
        lambda command: tool_run_command_async(command),
    ),
    Tool(
        "windbg_continue",
        "Resume execution (cdb 'g'). Returns when the target hits a breakpoint, exception, or exits. On timeout the server auto-breaks the target so you can recover.",
        {"type": "object", "properties": {"timeout": _int("Seconds before auto-break", 120)}},
        lambda timeout=120: tool_continue(float(timeout)),
    ),
    Tool(
        "windbg_continue_async",
        "Resume execution with cdb 'g' and return immediately. Does not install a timeout and never sends break-in by itself.",
        {"type": "object", "properties": {}},
        lambda: tool_continue_async(),
    ),
    Tool(
        "windbg_go",
        "Recommended safe continue: send cdb 'g', then wait for event/output without ever sending break-in on timeout.",
        {
            "type": "object",
            "properties": {
                "timeout": _int("Absolute seconds to wait; timeout does not pause the target", 120),
                "max_lines": _int("Maximum raw event lines to read", 2000),
                "quiet_timeout": _int("Return after this many quiet seconds once output has arrived, unless stop_on_exception=true and no exception was seen", 1),
                "stop_on_exception": _bool("When true, ignore quiet output gaps until exception-like event, prompt, process exit, or timeout", True),
                "filter_pattern": _str("Optional regex; when set, only matching event lines are returned"),
                "exclude_pattern": _str("Optional regex; matching event lines are removed before include filtering"),
                "ignore_case": _bool("Apply include/exclude regexes case-insensitively", False),
                "invert_match": _bool("With filter_pattern, keep non-matching lines instead of matching lines", False),
                "context_before": _int("Include this many lines before each filter_pattern match", 0),
                "context_after": _int("Include this many lines after each filter_pattern match", 0),
                "tail_lines": _int("Return only the last N filtered event lines"),
            },
        },
        lambda timeout=120, max_lines=2000, quiet_timeout=1, stop_on_exception=True,
        filter_pattern=None, exclude_pattern=None, ignore_case=False, invert_match=False, context_before=0,
        context_after=0, tail_lines=None: tool_go(
            float(timeout),
            int(max_lines),
            float(quiet_timeout),
            bool(stop_on_exception),
            filter_pattern,
            exclude_pattern,
            bool(ignore_case),
            bool(invert_match),
            int(context_before),
            int(context_after),
            int(tail_lines) if tail_lines is not None else None,
        ),
    ),
    Tool(
        "windbg_wait_for_event",
        "Wait for output/prompt from an async command without sending break-in on timeout. Use after windbg_continue_async.",
        {
            "type": "object",
            "properties": {
                "timeout": _int("Seconds to wait; timeout does not pause the target", 120),
                "max_lines": _int("Maximum output lines to return", 2000),
                "quiet_timeout": _int("Return after this many quiet seconds once output has arrived", 1),
                "stop_on_exception": _bool("When true, ignore quiet silence until an exception-like event or prompt arrives", False),
                "filter_pattern": _str("Optional regex; when set, only matching event lines are returned"),
                "exclude_pattern": _str("Optional regex; matching event lines are removed before include filtering"),
                "ignore_case": _bool("Apply include/exclude regexes case-insensitively", False),
                "invert_match": _bool("With filter_pattern, keep non-matching lines instead of matching lines", False),
                "context_before": _int("Include this many lines before each filter_pattern match", 0),
                "context_after": _int("Include this many lines after each filter_pattern match", 0),
                "tail_lines": _int("Return only the last N filtered event lines"),
            },
        },
        lambda timeout=120, max_lines=2000, quiet_timeout=1, stop_on_exception=False,
        filter_pattern=None, exclude_pattern=None, ignore_case=False, invert_match=False, context_before=0,
        context_after=0, tail_lines=None: tool_wait_for_event(
            float(timeout),
            int(max_lines),
            float(quiet_timeout),
            bool(stop_on_exception),
            filter_pattern,
            exclude_pattern,
            bool(ignore_case),
            bool(invert_match),
            int(context_before),
            int(context_after),
            int(tail_lines) if tail_lines is not None else None,
        ),
    ),
    Tool(
        "windbg_wait_exception_profile",
        "Wait for exception/crash output using a preset filter profile (default/tg/asan). Does not send break-in on timeout.",
        {
            "type": "object",
            "properties": {
                "timeout": _int("Absolute seconds to wait", 300),
                "profile": _enum("Preset filter profile", ["default", "tg", "asan"], "tg"),
                "max_lines": _int("Maximum raw event lines to read", 2000),
                "tail_lines": _int("Return only the last N filtered lines", 120),
            },
        },
        lambda timeout=300, profile="tg", max_lines=2000, tail_lines=120: tool_wait_exception_profile(
            float(timeout),
            profile,
            int(max_lines),
            int(tail_lines) if tail_lines is not None else None,
        ),
    ),
    Tool(
        "windbg_read_output",
        "Drain currently buffered cdb output without blocking and without sending break-in.",
        {
            "type": "object",
            "properties": {
                "lines": _int("Maximum raw buffered lines to read", 50),
                "filter_pattern": _str("Optional regex; when set, only matching lines are returned"),
                "exclude_pattern": _str("Optional regex; matching lines are removed before include filtering"),
                "ignore_case": _bool("Apply include/exclude regexes case-insensitively", False),
                "invert_match": _bool("With filter_pattern, keep non-matching lines instead of matching lines", False),
                "context_before": _int("Include this many lines before each filter_pattern match", 0),
                "context_after": _int("Include this many lines after each filter_pattern match", 0),
                "tail_lines": _int("Return only the last N filtered lines"),
            },
        },
        lambda lines=50, filter_pattern=None, exclude_pattern=None, ignore_case=False, invert_match=False,
        context_before=0, context_after=0, tail_lines=None: tool_read_output(
            int(lines),
            filter_pattern,
            exclude_pattern,
            bool(ignore_case),
            bool(invert_match),
            int(context_before),
            int(context_after),
            int(tail_lines) if tail_lines is not None else None,
        ),
    ),
    Tool(
        "windbg_step_in",
        "Single-step one instruction, stepping INTO calls (cdb 't').",
        {"type": "object", "properties": {}},
        lambda: tool_step_in(),
    ),
    Tool(
        "windbg_step_over",
        "Single-step one instruction, stepping OVER calls (cdb 'p').",
        {"type": "object", "properties": {}},
        lambda: tool_step_over(),
    ),
    Tool(
        "windbg_step_out",
        "Run until the current function returns (cdb 'gu').",
        {"type": "object", "properties": {}},
        lambda: tool_step_out(),
    ),
    Tool(
        "windbg_run_to",
        "Run until execution reaches a given address or symbol (cdb 'g <addr>').",
        {
            "type": "object",
            "properties": {
                "address": _str("Address or symbol like 'kernel32!CreateFileW'"),
                "timeout": _int("Seconds before auto-break", 120),
            },
            "required": ["address"],
        },
        lambda address, timeout=120: tool_run_to(address, float(timeout)),
    ),
    Tool(
        "windbg_set_breakpoint",
        "Set a software breakpoint at an address or symbol. Optional cdb-expression condition.",
        {
            "type": "object",
            "properties": {
                "location": _str("Address or symbol, e.g. 'main', 'mymod!Foo+0x42', '0x7ff7`12340000'"),
                "condition": _str("Optional cdb expression; bp continues if false"),
            },
            "required": ["location"],
        },
        lambda location, condition=None: tool_set_breakpoint(location, condition),
    ),
    Tool(
        "windbg_set_conditional_bp",
        "Build and set a conditional cdb breakpoint safely, including optional .printf logging and false-branch gc.",
        {
            "type": "object",
            "properties": {
                "location": _str("Address or symbol, e.g. 'mymod!Foo+0x42'"),
                "condition": _str("Optional cdb expression; true branch logs/stops, false branch can gc"),
                "print_expr": _str("Optional cdb expression to log with a generated .printf, e.g. '@rcx'"),
                "continue_if_false": _bool("If true, false condition executes gc", True),
                "stop_if": _str("Alias/override for condition when the expression specifically means 'stop here if true'"),
            },
            "required": ["location"],
        },
        lambda location, condition=None, print_expr=None, continue_if_false=True, stop_if=None: tool_set_conditional_bp(
            location,
            condition,
            print_expr,
            bool(continue_if_false),
            stop_if,
        ),
    ),
    Tool(
        "windbg_bp_template",
        "Set a breakpoint from an AI-friendly template: log this/args, log expression, stop on signed-negative, pointer range, or stack log.",
        {
            "type": "object",
            "properties": {
                "location": _str("Address or symbol for the breakpoint"),
                "template": _enum("Breakpoint template", ["log_this", "log_expr", "stop_signed_negative", "stop_pointer_range", "log_stack"], "log_this"),
                "expr": _str("Expression used by log_expr/stop_signed_negative/stop_pointer_range"),
                "stop_if": _str("Optional cdb condition; required for stop_pointer_range"),
                "stack": _int("Stack frames to log", 5),
            },
            "required": ["location"],
        },
        lambda location, template="log_this", expr=None, stop_if=None, stack=5: tool_bp_template(
            location,
            template,
            expr,
            stop_if,
            int(stack),
        ),
    ),
    Tool(
        "windbg_set_data_breakpoint",
        "Set a hardware data breakpoint (cdb 'ba'). Triggers on read/write/execute access.",
        {
            "type": "object",
            "properties": {
                "size": _enum("Access width in bytes", ["1", "2", "4", "8"]),
                "access": _enum("Access type: r=read, w=write, e=execute", ["r", "w", "e"]),
                "address": _str("Address to watch"),
            },
            "required": ["size", "access", "address"],
        },
        lambda size, access, address: tool_set_data_breakpoint(size, access, address),
    ),
    Tool(
        "windbg_watch_memory",
        "Set a hardware data breakpoint that logs IP, watched value, optional stack, then continues. Avoids hand-written ba/.printf escaping.",
        {
            "type": "object",
            "properties": {
                "address": _str("Address to watch"),
                "size": _enum("Access width in bytes", ["1", "2", "4", "8"], "8"),
                "access": _enum("Access type: r=read, w=write, e=execute", ["r", "w", "e"], "w"),
                "log_stack": _bool("Log kb 5 on each hit", True),
            },
            "required": ["address"],
        },
        lambda address, size="8", access="w", log_stack=True: tool_watch_memory(address, size, access, bool(log_stack)),
    ),
    Tool(
        "windbg_list_breakpoints",
        "List all configured breakpoints (cdb 'bl').",
        {"type": "object", "properties": {}},
        lambda: tool_list_breakpoints(),
    ),
    Tool(
        "windbg_save_breakpoints",
        "Persist current breakpoints using cdb .bpcmds into .windbg_mcp_breakpoints/<name>.cmd.",
        {"type": "object", "properties": {"name": _str("Breakpoint set name")}, "required": ["name"]},
        lambda name: tool_save_breakpoints(name),
    ),
    Tool(
        "windbg_load_breakpoints",
        "Restore a previously saved breakpoint set. Optionally clears existing breakpoints first.",
        {
            "type": "object",
            "properties": {
                "name": _str("Breakpoint set name"),
                "clear_existing": _bool("Run bc * before loading saved breakpoints", False),
            },
            "required": ["name"],
        },
        lambda name, clear_existing=False: tool_load_breakpoints(name, bool(clear_existing)),
    ),
    Tool(
        "windbg_clear_breakpoint",
        "Delete one or all breakpoints (cdb 'bc').",
        {"type": "object", "properties": {"spec": _str("BP id, range '0-3', or '*' for all")}},
        lambda spec="*": tool_clear_breakpoint(spec),
    ),
    Tool(
        "windbg_disable_breakpoint",
        "Disable a breakpoint without deleting it (cdb 'bd').",
        {"type": "object", "properties": {"spec": _str("BP id, range, or '*'")}, "required": ["spec"]},
        lambda spec: tool_disable_breakpoint(spec),
    ),
    Tool(
        "windbg_enable_breakpoint",
        "Re-enable a previously disabled breakpoint (cdb 'be').",
        {"type": "object", "properties": {"spec": _str("BP id, range, or '*'")}, "required": ["spec"]},
        lambda spec: tool_enable_breakpoint(spec),
    ),
    Tool(
        "windbg_registers",
        "Read the CPU registers. Output is parsed into a clean key=value table plus the raw cdb output.",
        {"type": "object", "properties": {"group": _enum("Register group", ["default", "fp", "xmm", "all"], "default")}},
        lambda group="default": tool_registers(group),
    ),
    Tool(
        "windbg_set_register",
        "Modify a CPU register, e.g. name='rax', value='0x42'.",
        {
            "type": "object",
            "properties": {"name": _str("Register name without @"), "value": _str("New value (cdb expression)")},
            "required": ["name", "value"],
        },
        lambda name, value: tool_set_register(name, value),
    ),
    Tool(
        "windbg_evaluate",
        "Evaluate a cdb expression (cdb '?'). Useful for arithmetic, symbol lookup, and casting.",
        {"type": "object", "properties": {"expression": _str("Any cdb expression, e.g. '@rax + 8' or 'poi(@rsp)'")}, "required": ["expression"]},
        lambda expression: tool_evaluate(expression),
    ),
    Tool(
        "windbg_call_stack",
        "Show the call stack of the current thread.",
        {
            "type": "object",
            "properties": {
                "count": _int("Max frames", 30),
                "mode": _enum("Stack format", ["default", "params", "frames", "verbose"], "default"),
            },
        },
        lambda count=30, mode="default": tool_call_stack(int(count), mode),
    ),
    Tool(
        "windbg_stack_find_thread",
        "Search all thread stacks for a regex/module/SP/address and optionally switch to the matching thread.",
        {
            "type": "object",
            "properties": {
                "pattern": _str("Regex/module/address to search in ~* stack output"),
                "sp": _str("Exact stack pointer/address to search literally"),
                "count": _int("Frames per thread", 20),
                "mode": _enum("Stack format", ["default", "params", "frames", "verbose"], "params"),
                "context_before": _int("Lines before match", 2),
                "context_after": _int("Lines after match", 8),
                "switch": _bool("Switch to the TID nearest the first match", False),
            },
        },
        lambda pattern=None, sp=None, count=20, mode="params", context_before=2, context_after=8, switch=False: tool_stack_find_thread(
            pattern,
            sp,
            int(count),
            mode,
            int(context_before),
            int(context_after),
            bool(switch),
        ),
    ),
    Tool(
        "windbg_shadow_stack",
        "Dump the CET hardware shadow stack using dps @ssp. Useful when HW-enforced stack protection is enabled.",
        {
            "type": "object",
            "properties": {
                "count": _int("Number of qwords to dump", 32),
                "address": _str("Shadow stack address/expression, default @ssp"),
            },
        },
        lambda count=32, address="@ssp": tool_shadow_stack(int(count), address),
    ),
    Tool(
        "windbg_shadow_stack_compare",
        "Dump normal stack and shadow stack side by side for quick return-address divergence checks.",
        {"type": "object", "properties": {"count": _int("Number of qwords to compare", 32)}},
        lambda count=32: tool_shadow_stack_compare(int(count)),
    ),
    Tool(
        "windbg_shadow_stack_return",
        "Resolve one shadow stack return slot: dps slot, nearest symbol, and disassembly at poi(slot).",
        {
            "type": "object",
            "properties": {
                "index": _int("Shadow stack slot index", 0),
                "disasm_count": _int("Instructions to disassemble at the return address", 8),
            },
        },
        lambda index=0, disasm_count=8: tool_shadow_stack_return(int(index), int(disasm_count)),
    ),
    Tool(
        "windbg_run_to_shadow_return",
        "Run to poi(@ssp+index*8). Async by default so long waits do not force break-in.",
        {
            "type": "object",
            "properties": {
                "index": _int("Shadow stack slot index", 0),
                "async_run": _bool("Send g and return immediately; use windbg_wait_for_event afterward", True),
                "timeout": _int("Sync timeout if async_run=false", 120),
            },
        },
        lambda index=0, async_run=True, timeout=120: tool_run_to_shadow_return(int(index), bool(async_run), float(timeout)),
    ),
    Tool(
        "windbg_disassemble",
        "Disassemble code forward. By default shows N instructions at an address; with function=true disassembles the whole function (cdb 'uf').",
        {
            "type": "object",
            "properties": {
                "address": _str("Address or symbol (default: current IP)"),
                "count": _int("Number of instructions when function=false", 16),
                "function": _bool("Disassemble the entire function ('uf')", False),
            },
        },
        lambda address=".", count=16, function=False: tool_disassemble(address, int(count), bool(function)),
    ),
    Tool(
        "windbg_disassemble_back",
        "Disassemble N instructions BEFORE an address (cdb 'ub'). Useful for seeing what led to the current IP.",
        {
            "type": "object",
            "properties": {
                "address": _str("Address or symbol (default: current IP)"),
                "count": _int("Number of instructions before the address", 8),
            },
        },
        lambda address=".", count=8: tool_disassemble_back(address, int(count)),
    ),
    Tool(
        "windbg_read_memory",
        "Read memory in a chosen format (byte/word/dword/qword/ascii/unicode/pointer).",
        {
            "type": "object",
            "properties": {
                "address": _str("Address or symbol"),
                "count": _int("Number of units", 32),
                "fmt": _enum("Display format", list(_MEM_FORMATS.keys()), "byte"),
            },
            "required": ["address"],
        },
        lambda address, count=32, fmt="byte": tool_read_memory(address, int(count), fmt),
    ),
    Tool(
        "windbg_write_memory",
        "Write memory in a chosen format (byte/word/dword/qword/ascii/unicode).",
        {
            "type": "object",
            "properties": {
                "address": _str("Address or symbol"),
                "values": _str("Space-separated values, or quoted string for ascii/unicode"),
                "fmt": _enum("Write format", list(_WRITE_FORMATS.keys()), "byte"),
            },
            "required": ["address", "values"],
        },
        lambda address, values, fmt="byte": tool_write_memory(address, values, fmt),
    ),
    Tool(
        "windbg_search_memory",
        "Search a memory range for a byte/string/dword/qword pattern.",
        {
            "type": "object",
            "properties": {
                "start": _str("Start address"),
                "length": _str("Length in cdb hex, e.g. '1000'"),
                "pattern": _str("Pattern. For bytes: '41 42 43'. For ascii/unicode: \"hello\""),
                "kind": _enum("Pattern type", ["bytes", "ascii", "unicode", "dword", "qword"], "bytes"),
            },
            "required": ["start", "length", "pattern"],
        },
        lambda start, length, pattern, kind="bytes": tool_search_memory(start, length, pattern, kind),
    ),
    Tool(
        "windbg_list_modules",
        "List loaded modules. Optional name filter (cdb 'lm m <pattern>').",
        {"type": "object", "properties": {"filter": _str("Module name glob, e.g. 'kernel*'")}},
        lambda filter="": tool_list_modules(filter),
    ),
    Tool(
        "windbg_module_info",
        "Show detailed info for one module (paths, version, symbols).",
        {"type": "object", "properties": {"name": _str("Module name without extension")}, "required": ["name"]},
        lambda name: tool_module_info(name),
    ),
    Tool(
        "windbg_list_threads",
        "List all threads in the current process.",
        {"type": "object", "properties": {}},
        lambda: tool_list_threads(),
    ),
    Tool(
        "windbg_switch_thread",
        "Switch debugger context to a specific thread index.",
        {"type": "object", "properties": {"index": _int("Thread index (from windbg_list_threads)")}, "required": ["index"]},
        lambda index: tool_switch_thread(int(index)),
    ),
    Tool(
        "windbg_switch_thread_by_tid",
        "Switch debugger context by OS thread id using cdb ~~[tid]s. Accepts values like '43110', '0x43110', or 'pid.tid'.",
        {"type": "object", "properties": {"tid": _str("OS thread id from stacks, e.g. the second half of 'Id: pid.tid'")}, "required": ["tid"]},
        lambda tid: tool_switch_thread_by_tid(tid),
    ),
    Tool(
        "windbg_list_processes",
        "List processes in the current debugger session (cdb '|').",
        {"type": "object", "properties": {}},
        lambda: tool_list_processes(),
    ),
    Tool(
        "windbg_find_symbols",
        "Search symbols by pattern across modules (cdb 'x'). Pattern: 'mod!*func*'.",
        {"type": "object", "properties": {"pattern": _str("Symbol pattern, e.g. 'kernel32!Create*'")}, "required": ["pattern"]},
        lambda pattern: tool_find_symbols(pattern),
    ),
    Tool(
        "windbg_address_to_symbol",
        "Find the nearest symbol to an address (cdb 'ln').",
        {"type": "object", "properties": {"address": _str("Address")}, "required": ["address"]},
        lambda address: tool_address_to_symbol(address),
    ),
    Tool(
        "windbg_locals",
        "Show local variables of the current frame (requires private symbols).",
        {"type": "object", "properties": {}},
        lambda: tool_locals(),
    ),
    Tool(
        "windbg_source_lines",
        "Show source code lines around an address (requires source path).",
        {"type": "object", "properties": {"address": _str("Address (default: current IP)")}},
        lambda address=".": tool_source_lines(address),
    ),
    Tool(
        "windbg_analyze_crash",
        "Run !analyze on the current state. Best after windbg_open_dump or on an unhandled exception.",
        {"type": "object", "properties": {"verbose": _bool("Use !analyze -v", True)}},
        lambda verbose=True: tool_analyze_crash(bool(verbose)),
    ),
    Tool(
        "windbg_peb",
        "Dump the Process Environment Block of the current process (cdb '!peb').",
        {"type": "object", "properties": {}},
        lambda: tool_peb(),
    ),
    Tool(
        "windbg_teb",
        "Dump the Thread Environment Block of the current thread (cdb '!teb').",
        {"type": "object", "properties": {}},
        lambda: tool_teb(),
    ),
    Tool(
        "windbg_heap",
        "Run !heap with optional arguments (e.g. '-s' for summary, '-p -a <addr>' to inspect a block).",
        {"type": "object", "properties": {"args": _str("Arguments to !heap")}},
        lambda args="": tool_heap(args),
    ),
    Tool(
        "windbg_handle",
        "Run !handle to inspect kernel handles in the target. Empty args lists all handles.",
        {"type": "object", "properties": {"args": _str("Arguments to !handle, e.g. '0 f File'")}},
        lambda args="": tool_handle(args),
    ),
    Tool(
        "windbg_address",
        "Describe a virtual address with !address. Filters noisy 'Building memory map' progress lines and can cap output.",
        {
            "type": "object",
            "properties": {
                "address": _str("Address (empty = list all regions)"),
                "timeout": _int("Seconds to wait for !address", 30),
                "max_lines": _int("Optional maximum output lines to return"),
            },
        },
        lambda address="", timeout=30, max_lines=None: tool_address(
            address,
            float(timeout),
            int(max_lines) if max_lines is not None else None,
        ),
    ),
    Tool(
        "windbg_dt",
        "Dump a structure type with cdb 'dt'. Optionally apply to an address.",
        {
            "type": "object",
            "properties": {"type_name": _str("Type, e.g. 'nt!_PEB' or 'mymod!FOO'"), "address": _str("Optional address")},
            "required": ["type_name"],
        },
        lambda type_name, address=None: tool_dt(type_name, address),
    ),
    Tool(
        "windbg_set_symbol_path",
        "Set the symbol search path (cdb '.sympath') and reload symbols. Use 'srv*c:\\sym*https://msdl.microsoft.com/download/symbols' for the public store.",
        {"type": "object", "properties": {"path": _str("Symbol path")}, "required": ["path"]},
        lambda path: tool_set_symbol_path(path),
    ),
    Tool(
        "windbg_reload_symbols",
        "Reload symbols (cdb '.reload'). Use force=true to discard cached symbols.",
        {"type": "object", "properties": {"force": _bool("Pass /f to .reload", False)}},
        lambda force=False: tool_reload_symbols(bool(force)),
    ),
    Tool(
        "windbg_set_source_path",
        "Set the source code search path (cdb '.srcpath').",
        {"type": "object", "properties": {"path": _str("Source path")}, "required": ["path"]},
        lambda path: tool_set_source_path(path),
    ),
    # --- Extra tools for heap/exploit/crash analysis ---
    Tool(
        "windbg_crash_triage",
        "Full crash triage in one call: !analyze -v + registers + call stack + exception record + fault address context. Best first tool after hitting a crash.",
        {"type": "object", "properties": {}},
        lambda: tool_crash_triage(),
    ),
    Tool(
        "windbg_heap_block_info",
        "Inspect a specific heap block: size, flags, neighbors, memory before/after. Use with ASAN crash addresses to understand overflow context.",
        {"type": "object", "properties": {"address": _str("Heap block address to inspect")}, "required": ["address"]},
        lambda address: tool_heap_block_info(address),
    ),
    Tool(
        "windbg_heap_neighbors",
        "Inspect a heap block plus bytes and pointer/symbol view before and after it.",
        {
            "type": "object",
            "properties": {
                "address": _str("Heap block address to inspect"),
                "before": _int("Bytes before address", 64),
                "after": _int("Bytes after address", 256),
            },
            "required": ["address"],
        },
        lambda address, before=64, after=256: tool_heap_neighbors(address, int(before), int(after)),
    ),
    Tool(
        "windbg_object_context",
        "One-call object/heap context: address eval, symbol, !address, !heap, qwords, bytes/pointers around, potential vtable, optional VRle::Span decode.",
        {
            "type": "object",
            "properties": {
                "address": _str("Object/address to inspect"),
                "before": _int("Bytes before address", 64),
                "after": _int("Bytes after address", 256),
                "span_count": _int("Optional VRle::Span count to decode from address", 0),
                "include_vtable": _bool("Try to resolve a potential vtable unless the region is clearly stack", True),
            },
            "required": ["address"],
        },
        lambda address, before=64, after=256, span_count=0, include_vtable=True: tool_object_context(
            address,
            int(before),
            int(after),
            int(span_count),
            bool(include_vtable),
        ),
    ),
    Tool(
        "windbg_thread_stacks",
        "Show call stacks for ALL threads simultaneously (cdb '~* kP'). Essential for race condition / UAF analysis.",
        {"type": "object", "properties": {}},
        lambda: tool_thread_stacks(),
    ),
    Tool(
        "windbg_exception_chain",
        "Show full exception chain: last event + exception record + context + stack at exception + SEH chain.",
        {"type": "object", "properties": {}},
        lambda: tool_exception_chain(),
    ),
    Tool(
        "windbg_find_vtable",
        "Check if an address contains a vtable pointer and resolve it to a symbol + disassembly. Useful for type confusion / UAF analysis.",
        {"type": "object", "properties": {"address": _str("Address that may contain a vtable pointer")}, "required": ["address"]},
        lambda address: tool_find_vtable(address),
    ),
    Tool(
        "windbg_find_vtable_owner",
        "Find heap object candidates whose first qword equals a vtable pointer. With heap_start+heap_length searches that range; otherwise parses heap ranges from !address -f:Heap and searches each range.",
        {
            "type": "object",
            "properties": {
                "vtable_addr": _str("Vtable pointer value to search for"),
                "heap_start": _str("Optional heap/range start address"),
                "heap_length": _str("Optional range length in cdb hex, e.g. '100000'"),
                "max_hits": _int("Maximum candidates to enrich with !heap -p -a", 64),
                "max_regions": _int("Maximum parsed heap ranges to search when heap_start/heap_length are omitted", 256),
                "region_timeout": _int("Seconds per heap range search before interrupting that debugger command", 20),
                "require_first_qword": _bool("Only report hits at offset 0 from the heap user block when block parsing succeeds", True),
            },
            "required": ["vtable_addr"],
        },
        lambda vtable_addr, heap_start=None, heap_length=None, max_hits=64, max_regions=256, region_timeout=20, require_first_qword=True: tool_find_vtable_owner(
            vtable_addr,
            heap_start,
            heap_length,
            int(max_hits),
            int(max_regions),
            float(region_timeout),
            bool(require_first_qword),
        ),
    ),
    Tool(
        "windbg_decode_spans",
        "Decode VRle::Span entries from memory. Layout assumed: {x:i16, y:i16, len:u16, cov:u8, raw7:u8}.",
        {
            "type": "object",
            "properties": {
                "address": _str("Address of the first span"),
                "count": _int("Number of 8-byte spans to decode", 16),
            },
            "required": ["address"],
        },
        lambda address, count=16: tool_decode_spans(address, int(count)),
    ),
    Tool(
        "windbg_asan_parse",
        "Parse ASAN crash context: exception record + context record + call stack at exception. Use when debugging ASAN-instrumented binaries.",
        {"type": "object", "properties": {}},
        lambda: tool_asan_parse(),
    ),
]


TOOLS_BY_NAME = {t.name: t for t in TOOLS}


# ---------------------------------------------------------------------------
# MCP JSON-RPC stdio loop
# ---------------------------------------------------------------------------


def _send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def _result(req_id: Any, result: Any) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def _error(req_id: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def _handle(request: dict[str, Any]) -> None:
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        _result(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
        return
    if method == "notifications/initialized":
        return  # nothing to do, no response for notifications
    if method == "ping":
        _result(req_id, {})
        return
    if method == "tools/list":
        _result(
            req_id,
            {
                "tools": [
                    {"name": t.name, "description": t.description, "inputSchema": t.schema}
                    for t in TOOLS
                ]
            },
        )
        return
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        tool = TOOLS_BY_NAME.get(name)
        if not tool:
            _error(req_id, -32601, f"unknown tool: {name}")
            return
        try:
            text = tool.handler(**args)
        except TypeError as e:
            text = f"ERROR: bad arguments for {name}: {e}"
        except Exception as e:
            text = f"ERROR: {type(e).__name__}: {e}"
        _result(req_id, {"content": [{"type": "text", "text": text}], "isError": False})
        return

    if req_id is not None:
        _error(req_id, -32601, f"method not found: {method}")


def main() -> int:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            request = json.loads(raw)
        except json.JSONDecodeError as e:
            _error(None, -32700, f"parse error: {e}")
            continue
        try:
            _handle(request)
        except Exception as e:
            req_id = request.get("id") if isinstance(request, dict) else None
            _error(req_id, -32603, f"internal error: {e}")
    # cleanup on EOF
    if SESSION.is_running():
        SESSION.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
