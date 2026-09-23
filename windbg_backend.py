"""Shared WinDbg/cdb backend used by windbg_mcp and mco_orchestrator.

This module owns cdb discovery, lifecycle and command I/O so the standalone
WinDbg MCP server and cross-debugger orchestrator cannot drift independently.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from queue import Empty, Queue

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

    @property
    def available(self) -> bool:
        return os.path.isfile(self.cdb_path) or shutil.which(self.cdb_path) is not None

    @property
    def connected(self) -> bool:
        return self.is_running()

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

    def close(self) -> str:
        return self.stop()

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


__all__ = [
    "CDB_PROMPT_RE",
    "CDB_PROMPT_PREFIX_RE",
    "CdbSession",
]
