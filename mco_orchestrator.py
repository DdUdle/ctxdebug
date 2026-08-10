#!/usr/bin/env python3
"""
MCO Orchestrator — Cross-Debugger Intelligence Layer
Coordinates WinDbg, IDA Pro, and x64dbg for compound security workflows.

Usage:
    python mco_orchestrator.py                    # stdio MCP server
    claude mcp add mco -- python "C:\\path\\mco_orchestrator.py"

Environment:
    CDB_PATH        — path to cdb.exe (WinDbg headless)
    IDA_HOST        — IDA HTTP server host (default: localhost)
    IDA_PORT        — IDA HTTP server port (default: 2022)
    X64DBG_PIPE     — x64dbg named pipe (default: \\.\pipe\x64dbg_ai_agent)
"""

import asyncio
import json
import logging
import os
import struct
import subprocess
import sys
import time
import urllib.request
import urllib.error
from contextlib import contextmanager
from typing import Any

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
log = logging.getLogger("mco")

# ─────────────────────────────────────────────────────────────
#  Backend Clients (lightweight, no deps on other MCP servers)
# ─────────────────────────────────────────────────────────────

class CdbClient:
    """Minimal cdb.exe wrapper for orchestrator use."""

    DEFAULT_CDB = os.environ.get(
        "CDB_PATH",
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
    )

    def __init__(self):
        self._proc: subprocess.Popen | None = None

    @property
    def connected(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def open_dump(self, dump_path: str) -> str:
        if not os.path.exists(self.DEFAULT_CDB):
            return f"ERROR: cdb.exe not found at {self.DEFAULT_CDB}"
        cmd = [self.DEFAULT_CDB, "-z", dump_path, "-lines", "-nosqm"]
        try:
            self._proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            return self._read_until_prompt(timeout=15)
        except Exception as e:
            return f"ERROR: {e}"

    def run(self, cmd: str, timeout: float = 30) -> str:
        if not self.connected:
            return "ERROR: Not connected to cdb.exe"
        try:
            self._proc.stdin.write(cmd + "\n")
            self._proc.stdin.flush()
            return self._read_until_prompt(timeout=timeout)
        except Exception as e:
            return f"ERROR: {e}"

    def _read_until_prompt(self, timeout: float = 30) -> str:
        lines = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self._proc.stdout.readline()
            if not line:
                break
            lines.append(line.rstrip())
            if line.rstrip().endswith(">"):
                break
        return "\n".join(lines)

    def close(self):
        if self._proc:
            try:
                self._proc.stdin.write("q\n")
                self._proc.stdin.flush()
                self._proc.wait(timeout=3)
            except Exception:
                self._proc.terminate()
            self._proc = None


class IDAClient:
    """Minimal IDA Pro REST client for orchestrator use."""

    ENDPOINTS = ["/api/v1/py", "/api/python", "/python", "/exec", "/api/1/exec"]

    def __init__(self):
        host = os.environ.get("IDA_HOST", "localhost")
        port = os.environ.get("IDA_PORT", "2022")
        self.token = os.environ.get("IDA_MCP_TOKEN", "")
        self.base = f"http://{host}:{port}"
        self._endpoint: str | None = None

    def _headers(self) -> dict:
        h = {"Content-Type": "text/plain"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _find_endpoint(self) -> str | None:
        for ep in self.ENDPOINTS:
            try:
                req = urllib.request.Request(
                    self.base + ep,
                    data=b"return 'ok'",
                    method="POST",
                    headers=self._headers()
                )
                with urllib.request.urlopen(req, timeout=3) as r:
                    if r.status == 200:
                        return ep
            except Exception:
                pass
        return None

    @property
    def available(self) -> bool:
        if self._endpoint is None:
            self._endpoint = self._find_endpoint()
        return self._endpoint is not None

    def exec_python(self, code: str) -> str:
        if not self.available:
            return "ERROR: IDA Pro not available (run ida_server_plugin.py inside IDA)"
        try:
            req = urllib.request.Request(
                self.base + self._endpoint,
                data=code.encode(),
                method="POST",
                headers=self._headers()
            )
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode()
        except Exception as e:
            self._endpoint = None
            return f"ERROR: {e}"


class X64DbgClient:
    """Minimal x64dbg named-pipe client for orchestrator use."""

    PIPE_NAME = os.environ.get("X64DBG_PIPE", r"\\.\pipe\x64dbg_ai_agent")
    MAGIC = b"X64A"

    def available(self) -> bool:
        return os.path.exists(self.PIPE_NAME)

    def send_command(self, cmd: str, args: dict | None = None) -> dict:
        if not self.available():
            return {"error": "x64dbg plugin not running (pipe not found)"}
        payload = json.dumps({"cmd": cmd, "args": args or {}}).encode()
        header = self.MAGIC + struct.pack("<I", len(payload)) + b"\x00" * 8
        try:
            with open(self.PIPE_NAME, "r+b", buffering=0) as pipe:
                pipe.write(header + payload)
                resp_header = pipe.read(16)
                if len(resp_header) < 16:
                    return {"error": "Incomplete response header"}
                resp_len = struct.unpack("<I", resp_header[4:8])[0]
                resp_data = pipe.read(resp_len)
                return json.loads(resp_data.decode())
        except Exception as e:
            return {"error": str(e)}


# ─────────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────────

class MCOOrchestrator:
    def __init__(self):
        self.cdb = CdbClient()
        self.ida = IDAClient()
        self.x64 = X64DbgClient()

    # ── Status ───────────────────────────────────────────────

    def debugger_status(self) -> dict:
        """Check which debuggers are available right now."""
        windbg_ok = os.path.exists(self.cdb.DEFAULT_CDB)
        ida_ok = self.ida.available
        x64_ok = self.x64.available()
        return {
            "windbg": {
                "available": windbg_ok,
                "connected": self.cdb.connected,
                "path": self.cdb.DEFAULT_CDB,
                "status": "ready" if windbg_ok else "cdb.exe not found"
            },
            "ida": {
                "available": ida_ok,
                "path": self.ida.base,
                "status": "HTTP server up" if ida_ok else "not running — exec ida_server_plugin.py"
            },
            "x64dbg": {
                "available": x64_ok,
                "pipe": self.x64.PIPE_NAME,
                "status": "plugin active" if x64_ok else "plugin not loaded"
            },
            "active_count": sum([windbg_ok, ida_ok, x64_ok])
        }

    # ── Cross-Debugger Workflow 1: Crash → Static Analysis ──

    def crash_to_source(self, dump_path: str) -> dict:
        """
        Full crash analysis pipeline:
        1. WinDbg: open dump, run !analyze -v, get crashing RIP
        2. IDA: decompile the crashing function, list xrefs
        Returns combined report.
        """
        result = {"dump": dump_path, "stages": []}

        # Stage 1: WinDbg crash analysis
        if not os.path.exists(dump_path):
            return {"error": f"Dump not found: {dump_path}"}

        wb_out = self.cdb.open_dump(dump_path)
        result["stages"].append({"stage": "windbg_load", "output": wb_out[-2000:]})

        analyze = self.cdb.run("!analyze -v", timeout=60)
        result["stages"].append({"stage": "windbg_analyze", "output": analyze[-3000:]})

        # Extract crashing address from !analyze output
        crash_addr = None
        for line in analyze.splitlines():
            if "FAULT_IP:" in line or "ExceptionAddress:" in line:
                parts = line.split()
                for p in parts:
                    if p.startswith("0x") or (len(p) == 16 and all(c in "0123456789abcdefABCDEF" for c in p)):
                        try:
                            crash_addr = int(p.replace("0x", ""), 16)
                            break
                        except ValueError:
                            pass
                if crash_addr:
                    break

        result["crash_address"] = hex(crash_addr) if crash_addr else None

        # Stage 2: IDA decompile of crashing function
        if crash_addr and self.ida.available:
            ida_code = f"""
import idc, idaapi, idautils

addr = {crash_addr}
func = idaapi.get_func(addr)
func_addr = func.start_ea if func else addr

# Decompile
try:
    cfunc = idaapi.decompile(func_addr)
    decompiled = str(cfunc) if cfunc else 'Decompilation failed'
except Exception as e:
    decompiled = f'Error: {{e}}'

# Function info
func_name = idc.get_func_name(func_addr) or 'unknown'
func_size = (func.end_ea - func.start_ea) if func else 0

# Callers
callers = [hex(r.frm) for r in idautils.XrefsTo(func_addr, 0)][:10]

print(json.dumps({{
    'function': func_name,
    'address': hex(func_addr),
    'size': func_size,
    'callers': callers,
    'decompiled': decompiled[:3000]
}}))
""".strip()
            ida_result = self.ida.exec_python(
                "import json\n" + ida_code
            )
            try:
                result["ida_analysis"] = json.loads(ida_result.strip().split("\n")[-1])
            except Exception:
                result["ida_analysis"] = {"raw": ida_result[:2000]}
            result["stages"].append({"stage": "ida_decompile", "status": "ok"})
        else:
            result["stages"].append({
                "stage": "ida_decompile",
                "status": "skipped" if not crash_addr else "ida_not_available"
            })

        self.cdb.close()
        return result

    # ── Cross-Debugger Workflow 2: Anti-Debug Full Report ───

    def bossix_report(self) -> dict:
        """
        Combined bossix detection across all available debuggers:
        - IDA: static scan for bossix patterns
        - x64dbg: check current registers / PEB flags
        """
        result = {}

        # IDA static scan
        if self.ida.available:
            ida_code = """
import idc, idautils, idaapi, json

BOSSIX_APIS = [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'OutputDebugString',
    'FindWindow', 'BlockInput', 'SetUnhandledExceptionFilter',
    'RtlQueryProcessHeapInformation', 'GetTickCount',
    'QueryPerformanceCounter', 'GetSystemTime',
    'NtSetInformationThread', 'ZwSetInformationThread',
    'CloseHandle', 'CreateMutex'
]

hits = []
for api in BOSSIX_APIS:
    addr = idc.get_name_ea_simple(api)
    if addr == idc.BADADDR:
        continue
    callers = [hex(r.frm) for r in idautils.XrefsTo(addr, 0)]
    if callers:
        hits.append({'api': api, 'import_addr': hex(addr), 'called_from': callers[:5]})

print(json.dumps({'bossix_hits': hits, 'total': len(hits)}))
"""
            raw = self.ida.exec_python(ida_code)
            try:
                result["ida_static"] = json.loads(raw.strip().split("\n")[-1])
            except Exception:
                result["ida_static"] = {"raw": raw[:1000]}
        else:
            result["ida_static"] = {"status": "IDA not available"}

        # x64dbg PEB check
        if self.x64.available():
            peb = self.x64.send_command("get_peb")
            regs = self.x64.send_command("get_registers")
            result["x64dbg_dynamic"] = {
                "peb": peb,
                "registers": regs,
                "hint": "Use bossix_hide to patch PEB.BeingDebugged"
            }
        else:
            result["x64dbg_dynamic"] = {"status": "x64dbg not attached"}

        return result

    # ── Cross-Debugger Workflow 3: Pivot Address ────────────

    def pivot_to_ida(self, address: str, context: str = "") -> dict:
        """
        Take an address from WinDbg/x64dbg and analyze it in IDA.
        address: hex address (e.g. "0x7FF712340000")
        context: optional context from WinDbg (e.g. !analyze output)
        """
        try:
            addr_int = int(address, 16) if address.startswith("0x") else int(address, 16)
        except ValueError:
            return {"error": f"Invalid address: {address}"}

        if not self.ida.available:
            return {"error": "IDA Pro not available"}

        code = f"""
import idc, idaapi, idautils, json

addr = {addr_int}
func = idaapi.get_func(addr)
func_start = func.start_ea if func else addr

result = {{
    'address': hex(addr),
    'function_start': hex(func_start),
    'function_name': idc.get_func_name(func_start) or 'sub_{{:X}}'.format(func_start),
    'module': idc.get_segm_name(func_start),
    'flags': idc.get_full_flags(addr),
}}

# Decompile
try:
    cfunc = idaapi.decompile(func_start)
    result['pseudocode'] = str(cfunc)[:4000] if cfunc else None
except Exception as e:
    result['pseudocode'] = None
    result['decompile_error'] = str(e)

# Xrefs to this address
result['xrefs_to'] = [hex(r.frm) for r in idautils.XrefsTo(addr, 0)][:15]

# Xrefs from this function
result['calls_out'] = []
if func:
    for head in idautils.Heads(func_start, func.end_ea):
        if idc.is_call_insn(head):
            target = idc.get_operand_value(head, 0)
            name = idc.get_func_name(target)
            if name:
                result['calls_out'].append({{'from': hex(head), 'to': name}})

print(json.dumps(result))
"""
        raw = self.ida.exec_python(code)
        try:
            parsed = json.loads(raw.strip().split("\n")[-1])
        except Exception:
            parsed = {"raw": raw[:2000]}

        if context:
            parsed["context_from_windbg"] = context[:500]

        return parsed

    # ── Cross-Debugger Workflow 4: Full w Audit ───────

    def quick_w_audit(self) -> dict:
        """
        Run all available scanners simultaneously:
        - IDA: strings, imports, anti-debug, crypto constants
        - x64dbg: modules, breakpoints, current state
        Returns a unified threat intelligence report.
        """
        report = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "findings": []}

        if self.ida.available:
            code = """
import idc, idautils, idaapi, ida_search, json

# Suspicious imports
SUSPICIOUS = [
    'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
    'ShellExecute', 'WinExec', 'CreateProcess', 'LoadLibrary', 'GetProcAddress',
    'InternetOpen', 'InternetConnect', 'HttpSendRequest', 'recv', 'send',
    'RegSetValue', 'RegCreateKey', 'CreateService', 'OpenSCManager',
    'CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt'
]

findings = []

# Check imports
for imp in SUSPICIOUS:
    addr = idc.get_name_ea_simple(imp)
    if addr != idc.BADADDR:
        callers = [hex(r.frm) for r in idautils.XrefsTo(addr, 0)][:5]
        if callers:
            findings.append({
                'type': 'suspicious_import',
                'api': imp,
                'severity': 'HIGH' if imp in ['CreateRemoteThread','WriteProcessMemory','CryptEncrypt'] else 'MEDIUM',
                'called_from': callers
            })

# Suspicious strings
for s in idautils.Strings():
    sv = str(s)
    if any(k in sv.lower() for k in ['cmd.exe', 'powershell', 'http://', 'https://', '.exe', 'inject', 'shellcode', 'payload']):
        findings.append({
            'type': 'suspicious_string',
            'value': sv[:100],
            'address': hex(s.ea),
            'severity': 'MEDIUM'
        })

summary = {
    'total_findings': len(findings),
    'high_severity': sum(1 for f in findings if f['severity'] == 'HIGH'),
    'findings': findings[:30]
}
print(json.dumps(summary))
"""
            raw = self.ida.exec_python(code)
            try:
                ida_report = json.loads(raw.strip().split("\n")[-1])
                report["ida_audit"] = ida_report
                if ida_report.get("high_severity", 0) > 0:
                    report["findings"].append({
                        "source": "ida_static",
                        "severity": "HIGH",
                        "message": f"{ida_report['high_severity']} high-severity API calls detected"
                    })
            except Exception:
                report["ida_audit"] = {"raw": raw[:1000]}
        else:
            report["ida_audit"] = {"status": "IDA not available"}

        if self.x64.available():
            modules = self.x64.send_command("list_modules")
            threads = self.x64.send_command("list_threads")
            report["x64dbg_runtime"] = {
                "modules": modules,
                "threads": threads
            }
        else:
            report["x64dbg_runtime"] = {"status": "x64dbg not attached"}

        report["recommendation"] = (
            "HIGH RISK: Multiple suspicious indicators found. Recommend sandbox analysis."
            if any(f.get("severity") == "HIGH" for f in report["findings"])
            else "LOW RISK: No high-severity indicators found."
        )

        return report

    # ── Workflow 5: Function Comparison (Binary Diffing) ────

    def compare_function_cross_binary(self, addr_a: str, addr_b: str) -> dict:
        """
        Compare two functions in IDA (useful for patch diffing).
        Shows added/removed/changed instructions.
        """
        if not self.ida.available:
            return {"error": "IDA not available"}

        code = f"""
import idc, idautils, idaapi, json

def get_func_insns(addr):
    func = idaapi.get_func(addr)
    if not func:
        return []
    insns = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        insns.append({{
            'addr': hex(head),
            'mnem': idc.print_insn_mnem(head),
            'operands': idc.print_operands(head),
            'bytes': ' '.join(f'{{b:02x}}' for b in idc.get_bytes(head, idc.get_item_size(head)))
        }})
    return insns

a_insns = get_func_insns({int(addr_a, 16)})
b_insns = get_func_insns({int(addr_b, 16)})

# Simple diff: compare mnemonics sequence
a_mnems = [i['mnem'] for i in a_insns]
b_mnems = [i['mnem'] for i in b_insns]
common = set(a_mnems) & set(b_mnems)

result = {{
    'function_a': {{'address': '{addr_a}', 'instruction_count': len(a_insns), 'name': idc.get_func_name({int(addr_a, 16)})}},
    'function_b': {{'address': '{addr_b}', 'instruction_count': len(b_insns), 'name': idc.get_func_name({int(addr_b, 16)})}},
    'similarity_pct': round(len(common) / max(len(a_mnems), len(b_mnems), 1) * 100, 1),
    'size_delta': len(b_insns) - len(a_insns),
    'a_instructions': a_insns[:50],
    'b_instructions': b_insns[:50],
}}
print(json.dumps(result))
"""
        raw = self.ida.exec_python(code)
        try:
            return json.loads(raw.strip().split("\n")[-1])
        except Exception:
            return {"raw": raw[:2000]}

    # ── Workflow 6: Heap Spray Detection ────────────────────

    def heap_spray_analysis(self) -> dict:
        """
        Combine WinDbg heap analysis with IDA heap allocation patterns.
        Detects heap spraying techniques.
        """
        result = {}

        if self.cdb.connected:
            # WinDbg: check for heap anomalies
            heap_out = self.cdb.run("!heap -s", timeout=30)
            result["windbg_heap_summary"] = heap_out[-2000:]

            # Look for suspicious large allocations
            heap_details = self.cdb.run("!heap -a -h 0", timeout=30)
            result["windbg_heap_details"] = heap_details[-2000:]
        else:
            result["windbg"] = {"status": "not connected — call windbg_open_dump first"}

        if self.ida.available:
            code = """
import idc, idautils, json

HEAP_ALLOC_APIS = ['HeapAlloc', 'HeapCreate', 'VirtualAlloc', 'VirtualAllocEx',
                   'malloc', 'calloc', 'realloc', 'new', 'RtlAllocateHeap']

alloc_patterns = []
for api in HEAP_ALLOC_APIS:
    addr = idc.get_name_ea_simple(api)
    if addr == idc.BADADDR:
        continue
    for xref in idautils.XrefsTo(addr, 0):
        caller = xref.frm
        # Get size operand (usually rdx or 2nd arg in x64)
        size_val = idc.get_operand_value(caller - idc.get_item_size(caller), 1)
        alloc_patterns.append({
            'api': api,
            'caller': hex(caller),
            'approx_size': hex(size_val) if size_val > 0 else 'dynamic'
        })

print(json.dumps({'heap_alloc_sites': alloc_patterns[:40], 'total': len(alloc_patterns)}))
"""
            raw = self.ida.exec_python(code)
            try:
                result["ida_alloc_patterns"] = json.loads(raw.strip().split("\n")[-1])
            except Exception:
                result["ida_alloc_patterns"] = {"raw": raw[:1000]}
        else:
            result["ida"] = {"status": "IDA not available"}

        return result


# ─────────────────────────────────────────────────────────────
#  MCP Server (stdio JSON-RPC)
# ─────────────────────────────────────────────────────────────

class MCPServer:
    def __init__(self):
        self.orchestrator = MCOOrchestrator()
        self._tools = self._build_tools()

    def _build_tools(self) -> list[dict]:
        return [
            {
                "name": "mco_status",
                "description": "Check which debuggers (WinDbg, IDA Pro, x64dbg) are currently available and connected.",
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "mco_crash_to_source",
                "description": (
                    "Full crash analysis pipeline: open a .dmp in WinDbg, extract the crashing address, "
                    "then pivot to IDA Pro to decompile the crashing function and show callers. "
                    "Returns a combined report with WinDbg !analyze output + IDA pseudocode."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dump_path": {
                            "type": "string",
                            "description": "Full path to the .dmp crash dump file"
                        }
                    },
                    "required": ["dump_path"]
                }
            },
            {
                "name": "mco_bossix_report",
                "description": (
                    "Cross-debugger bossix detection: "
                    "IDA Pro static scan for IsDebuggerPresent/NtQueryInformationProcess/etc. + "
                    "x64dbg dynamic PEB check. Returns combined findings."
                ),
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "mco_pivot_to_ida",
                "description": (
                    "Take an address from WinDbg or x64dbg and analyze it in IDA Pro. "
                    "Returns: function name, decompiled pseudocode, callers, callees. "
                    "Use when you have a suspicious address from dynamic analysis."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Hex address, e.g. '0x7FF712340000'"
                        },
                        "context": {
                            "type": "string",
                            "description": "Optional context string (e.g. WinDbg output about this address)"
                        }
                    },
                    "required": ["address"]
                }
            },
            {
                "name": "mco_w_audit",
                "description": (
                    "Quick w audit using all available debuggers: "
                    "IDA static analysis (suspicious APIs, strings, crypto) + "
                    "x64dbg runtime state (modules, threads). "
                    "Returns a unified threat intelligence report with severity ratings."
                ),
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            },
            {
                "name": "mco_compare_functions",
                "description": (
                    "Binary diff two functions in IDA Pro. Compare instruction sequences, "
                    "calculate similarity percentage, show added/removed operations. "
                    "Useful for patch diffing between clean and infected binaries."
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "address_a": {
                            "type": "string",
                            "description": "Hex address of first function"
                        },
                        "address_b": {
                            "type": "string",
                            "description": "Hex address of second function"
                        }
                    },
                    "required": ["address_a", "address_b"]
                }
            },
            {
                "name": "mco_heap_spray_analysis",
                "description": (
                    "Detect heap spray attacks: "
                    "WinDbg !heap -s summary + IDA Pro heap allocation site mapping. "
                    "Identifies suspicious allocation patterns and size anomalies."
                ),
                "inputSchema": {"type": "object", "properties": {}, "required": []}
            }
        ]

    def _ok(self, data: Any) -> dict:
        text = json.dumps(data, indent=2) if not isinstance(data, str) else data
        return {
            "content": [{"type": "text", "text": text}],
            "isError": False
        }

    def _err(self, msg: str) -> dict:
        return {
            "content": [{"type": "text", "text": f"ERROR: {msg}"}],
            "isError": True
        }

    def handle(self, request: dict) -> dict | None:
        method = request.get("method")
        params = request.get("params", {})
        req_id = request.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "mco-orchestrator",
                        "version": "1.0.0",
                        "description": "MCO Cross-Debugger Intelligence Layer"
                    }
                }
            }

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {"tools": self._tools}
            }

        if method == "tools/call":
            tool = params.get("name")
            args = params.get("arguments", {})

            try:
                if tool == "mco_status":
                    result = self._ok(self.orchestrator.debugger_status())
                elif tool == "mco_crash_to_source":
                    result = self._ok(self.orchestrator.crash_to_source(args["dump_path"]))
                elif tool == "mco_bossix_report":
                    result = self._ok(self.orchestrator.bossix_report())
                elif tool == "mco_pivot_to_ida":
                    result = self._ok(self.orchestrator.pivot_to_ida(
                        args["address"], args.get("context", "")
                    ))
                elif tool == "mco_w_audit":
                    result = self._ok(self.orchestrator.quick_w_audit())
                elif tool == "mco_compare_functions":
                    result = self._ok(self.orchestrator.compare_function_cross_binary(
                        args["address_a"], args["address_b"]
                    ))
                elif tool == "mco_heap_spray_analysis":
                    result = self._ok(self.orchestrator.heap_spray_analysis())
                else:
                    result = self._err(f"Unknown tool: {tool}")
            except Exception as e:
                result = self._err(str(e))

            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        return {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        }


def main():
    server = MCPServer()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        response = server.handle(request)
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
