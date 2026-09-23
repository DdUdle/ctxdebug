#!/usr/bin/env python3
r"""
MCO Orchestrator — Cross-Debugger Intelligence Layer
Coordinates WinDbg, IDA Pro, and x64dbg for compound security workflows.

Usage:
    python mco_orchestrator.py                    # stdio MCP server
    claude mcp add mco -- python "C:\path\mco_orchestrator.py"

Environment:
    WINDBG_MCP_CDB  — path to cdb.exe (shared with windbg_mcp)
    IDA_MCP_HOST    — IDA HTTP server host (shared with ida_mcp)
    IDA_MCP_PORT    — IDA HTTP server port (shared with ida_mcp)
    X64DBG_PIPE     — x64dbg named pipe (default: \\.\pipe\x64dbg_ai_agent)
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from contextlib import contextmanager
from typing import Any

from agent.bridge import X64DbgBridge
from ida_mcp import IDAClient
from windbg_backend import CdbSession
from mco_common import serve_stdio, text_error, text_result

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
log = logging.getLogger("mco")

# ─────────────────────────────────────────────────────────────
#  Shared debugger backends
# ─────────────────────────────────────────────────────────────
# IDA transport/API lives in ida_mcp.IDAClient.
# WinDbg/cdb lifecycle lives in windbg_backend.CdbSession.
# x64dbg transport/API lives in agent.bridge.X64DbgBridge.

# ─────────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────────

def _parse_hex_token(token: str) -> int | None:
    cleaned = token.strip().strip(",;:()[]{}").replace("`", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned or any(ch not in "0123456789abcdefABCDEF" for ch in cleaned):
        return None
    try:
        return int(cleaned, 16)
    except ValueError:
        return None


def _extract_crash_address(analyze_output: str) -> int | None:
    """Extract the faulting runtime address from common WinDbg !analyze output."""
    lines = analyze_output.splitlines()
    markers = ("FAULT_IP:", "FAULTING_IP:", "ExceptionAddress:")
    for index, line in enumerate(lines):
        if not any(marker in line for marker in markers):
            continue
        candidates = line.split()
        for nearby in lines[index + 1:index + 4]:
            candidates.extend(nearby.split())
        for token in candidates:
            value = _parse_hex_token(token)
            if value is not None and value > 0xFFFF:
                return value
    return None


def _extract_module_info(lm_output: str, address: int | None = None) -> dict | None:
    """Parse module bounds/name from WinDbg `lm a <address>` output."""
    for line in lm_output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        start = _parse_hex_token(parts[0])
        end = _parse_hex_token(parts[1])
        if start is None or end is None or end <= start:
            continue
        if address is not None and not (start <= address < end):
            continue
        return {
            "base": start,
            "end": end,
            "name": parts[2],
        }
    return None


def _extract_module_base(lm_output: str, address: int | None = None) -> int | None:
    """Compatibility helper returning only the WinDbg runtime module base."""
    info = _extract_module_info(lm_output, address)
    return info["base"] if info else None


def _runtime_to_rva(runtime_address: int, runtime_module_base: int) -> int:
    if runtime_module_base < 0 or runtime_address < runtime_module_base:
        raise ValueError("Runtime address is below module base")
    return runtime_address - runtime_module_base


def _find_runtime_module(modules: list[dict], address: int) -> dict | None:
    """Find the runtime module containing an address from x64dbg modules.list."""
    for module in modules:
        base_raw = module.get("base")
        size_raw = module.get("size", 0)
        try:
            base = int(base_raw, 16) if isinstance(base_raw, str) else int(base_raw)
            size = int(size_raw, 0) if isinstance(size_raw, str) else int(size_raw)
        except (TypeError, ValueError):
            continue
        if size > 0 and base <= address < base + size:
            return {**module, "_base_int": base}
    return None


class MCOOrchestrator:
    def __init__(self):
        self.cdb = CdbSession()
        self.ida = IDAClient()
        pipe_name = os.environ.get("X64DBG_PIPE") or X64DbgBridge.PIPE_NAME
        self.x64 = X64DbgBridge(pipe_name=pipe_name)
        self._async_runner = asyncio.Runner()

    def close(self):
        try:
            if self.x64.connected:
                self._async_runner.run(self.x64.disconnect())
        finally:
            self._async_runner.close()

    def _run_async(self, awaitable):
        return self._async_runner.run(awaitable)

    async def _ensure_x64(self) -> bool:
        return self.x64.connected or await self.x64.connect()

    def _x64_available(self) -> bool:
        return bool(self._run_async(self._ensure_x64()))

    def _x64_bossix_snapshot(self) -> dict:
        async def collect():
            if not await self._ensure_x64():
                return {"error": "x64dbg plugin not running"}

            peb = await self.x64.get_peb()
            registers = await self.x64.get_registers()
            snapshot = {"peb": peb, "registers": registers}

            if isinstance(peb, dict) and peb.get("error"):
                return {**snapshot, "error": f"process.peb failed: {peb['error']}"}
            if registers is None:
                return {**snapshot, "error": "registers.get_all failed"}

            return snapshot

        return self._run_async(collect())

    def _x64_modules_snapshot(self) -> dict:
        async def collect():
            if not await self._ensure_x64():
                return {"error": "x64dbg plugin not running"}
            return {"modules": await self.x64.get_modules()}

        return self._run_async(collect())

    def _x64_runtime_snapshot(self) -> dict:
        async def collect():
            if not await self._ensure_x64():
                return {"error": "x64dbg plugin not running"}

            modules = await self.x64.get_modules()
            threads = await self.x64.get_threads()
            snapshot = {"modules": modules, "threads": threads}

            if not modules:
                return {**snapshot, "error": "modules.list returned no modules"}
            if not threads:
                return {**snapshot, "error": "threads.list returned no threads"}

            return snapshot

        return self._run_async(collect())

    # ── Status ───────────────────────────────────────────────

    def debugger_status(self) -> dict:
        """Check which debuggers are available right now."""
        windbg_ok = self.cdb.available
        ida_ok = self.ida.ping()
        x64_ok = self._x64_available()
        return {
            "windbg": {
                "available": windbg_ok,
                "connected": self.cdb.connected,
                "path": self.cdb.cdb_path,
                "status": "ready" if windbg_ok else "cdb.exe not found"
            },
            "ida": {
                "available": ida_ok,
                "path": self.ida.base,
                "status": "HTTP server up" if ida_ok else "not running — exec ida_server_plugin.py"
            },
            "x64dbg": {
                "available": x64_ok,
                "pipe": self.x64.pipe_name,
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

        # Extract runtime fault address, then normalize through RVA before IDA.
        crash_addr = _extract_crash_address(analyze)
        result["crash_address"] = hex(crash_addr) if crash_addr else None

        runtime_base = None
        runtime_module = None
        rva = None
        if crash_addr:
            lm_out = self.cdb.run(f"lm a {crash_addr:#x}", timeout=10)
            result["stages"].append({"stage": "windbg_module_lookup", "output": lm_out[-1500:]})
            module_info = _extract_module_info(lm_out, crash_addr)
            if module_info:
                runtime_base = module_info["base"]
                runtime_module = module_info["name"]
                rva = _runtime_to_rva(crash_addr, runtime_base)

        result["address_normalization"] = {
            "runtime_address": hex(crash_addr) if crash_addr is not None else None,
            "runtime_module_base": hex(runtime_base) if runtime_base is not None else None,
            "runtime_module": runtime_module,
            "rva": hex(rva) if rva is not None else None,
        }

        # Stage 2: IDA decompile using IDA imagebase + runtime RVA.
        if rva is not None and self.ida.ping():
            ida_code = f"""
import os
import idc, idaapi, idautils

runtime_address = {crash_addr}
runtime_module_base = {runtime_base}
runtime_module = {json.dumps(runtime_module)}
rva = {rva}
ida_imagebase = idaapi.get_imagebase()
ida_root = idc.get_root_filename() or ''
runtime_stem = os.path.splitext(os.path.basename(runtime_module or ''))[0].lower()
ida_stem = os.path.splitext(os.path.basename(ida_root))[0].lower()

if runtime_stem and ida_stem and runtime_stem != ida_stem:
    print(json.dumps({{
        'error': 'ida_module_mismatch',
        'runtime_module': runtime_module,
        'ida_root_filename': ida_root,
        'runtime_address': hex(runtime_address),
        'rva': hex(rva),
    }}))
else:
    addr = ida_imagebase + rva
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
        'runtime_address': hex(runtime_address),
        'runtime_module_base': hex(runtime_module_base),
        'runtime_module': runtime_module,
        'ida_root_filename': ida_root,
        'rva': hex(rva),
        'ida_imagebase': hex(ida_imagebase),
        'ida_address': hex(addr),
        'function_address': hex(func_addr),
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
            ida_status = result["ida_analysis"].get("error", "ok")
            result["stages"].append({"stage": "ida_decompile", "status": ida_status})
        else:
            if not crash_addr:
                status = "fault_address_unresolved"
            elif rva is None:
                status = "runtime_module_base_unresolved"
            else:
                status = "ida_not_available"
            result["stages"].append({"stage": "ida_decompile", "status": status})

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
        if self.ida.ping():
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

        # x64dbg dynamic snapshot through the shared bridge client.
        x64_snapshot = self._x64_bossix_snapshot()
        if "error" not in x64_snapshot:
            result["x64dbg_dynamic"] = {
                **x64_snapshot,
                "hint": "Use bossix_hide to patch PEB.BeingDebugged"
            }
        else:
            result["x64dbg_dynamic"] = {"status": "x64dbg not attached", **x64_snapshot}

        return result

    # ── Cross-Debugger Workflow 3: Pivot Address ────────────

    def pivot_to_ida(
        self,
        address: str,
        context: str = "",
        runtime_module_base: str = "",
    ) -> dict:
        """
        Normalize a runtime address through RVA before analyzing it in IDA.

        If runtime_module_base is omitted, the orchestrator tries to resolve the
        containing module from the live x64dbg modules list. If normalization is
        unavailable, the address is only accepted when it is already mapped in
        the current IDA database.
        """
        try:
            addr_int = int(address, 16)
        except (TypeError, ValueError):
            return {"error": f"Invalid address: {address}"}

        if not self.ida.ping():
            return {"error": "IDA Pro not available"}

        runtime_base = None
        module_name = None
        normalization_source = None

        if runtime_module_base:
            try:
                runtime_base = int(runtime_module_base, 16)
                normalization_source = "explicit_runtime_module_base"
            except (TypeError, ValueError):
                return {"error": f"Invalid runtime_module_base: {runtime_module_base}"}
        else:
            x64_snapshot = self._x64_modules_snapshot()
            if "error" not in x64_snapshot:
                module = _find_runtime_module(x64_snapshot.get("modules", []), addr_int)
                if module:
                    runtime_base = module["_base_int"]
                    module_name = module.get("name")
                    normalization_source = "x64dbg_modules"

        rva = _runtime_to_rva(addr_int, runtime_base) if runtime_base is not None else None
        rva_literal = "None" if rva is None else str(rva)
        module_literal = repr(module_name)

        code = f"""
import os
import idc, idaapi, idautils, ida_segment, json

input_addr = {addr_int}
rva = {rva_literal}
runtime_module = {module_literal}
ida_imagebase = idaapi.get_imagebase()
ida_root = idc.get_root_filename() or ''
runtime_stem = os.path.splitext(os.path.basename(runtime_module or ''))[0].lower()
ida_stem = os.path.splitext(os.path.basename(ida_root))[0].lower()

if rva is not None and runtime_stem and ida_stem and runtime_stem != ida_stem:
    print(json.dumps({{
        'error': 'ida_module_mismatch',
        'runtime_module': runtime_module,
        'ida_root_filename': ida_root,
        'input_address': hex(input_addr),
        'rva': hex(rva),
    }}))
else:
    addr = ida_imagebase + rva if rva is not None else input_addr
    segment = ida_segment.getseg(addr)

    if segment is None:
        print(json.dumps({{
            'error': 'address_not_mapped_in_ida',
            'input_address': hex(input_addr),
            'rva': hex(rva) if rva is not None else None,
            'ida_imagebase': hex(ida_imagebase),
            'candidate_ida_address': hex(addr),
        }}))
    else:
        func = idaapi.get_func(addr)
        func_start = func.start_ea if func else addr

        result = {{
            'input_address': hex(input_addr),
            'rva': hex(rva) if rva is not None else None,
            'ida_imagebase': hex(ida_imagebase),
            'ida_root_filename': ida_root,
            'ida_address': hex(addr),
            'function_start': hex(func_start),
            'function_name': idc.get_func_name(func_start) or 'sub_{{:X}}'.format(func_start),
            'module': idc.get_segm_name(func_start),
            'flags': idc.get_full_flags(addr),
        }}

        try:
            cfunc = idaapi.decompile(func_start)
            result['pseudocode'] = str(cfunc)[:4000] if cfunc else None
        except Exception as e:
            result['pseudocode'] = None
            result['decompile_error'] = str(e)

        result['xrefs_to'] = [hex(r.frm) for r in idautils.XrefsTo(addr, 0)][:15]
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

        parsed["address_normalization"] = {
            "runtime_address": hex(addr_int),
            "runtime_module_base": hex(runtime_base) if runtime_base is not None else None,
            "rva": hex(rva) if rva is not None else None,
            "runtime_module": module_name,
            "source": normalization_source or "already_mapped_ida_address",
        }
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

        if self.ida.ping():
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

        x64_snapshot = self._x64_runtime_snapshot()
        if "error" not in x64_snapshot:
            report["x64dbg_runtime"] = x64_snapshot
        else:
            report["x64dbg_runtime"] = {"status": "x64dbg not attached", **x64_snapshot}

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
        try:
            addr_a_int = int(addr_a, 16)
            addr_b_int = int(addr_b, 16)
        except (TypeError, ValueError):
            return {"error": f"Invalid address: {addr_a!r} / {addr_b!r}"}
        addr_a_repr = json.dumps(str(addr_a))
        addr_b_repr = json.dumps(str(addr_b))

        if not self.ida.ping():
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

a_insns = get_func_insns({addr_a_int})
b_insns = get_func_insns({addr_b_int})

# Simple diff: compare mnemonics sequence
a_mnems = [i['mnem'] for i in a_insns]
b_mnems = [i['mnem'] for i in b_insns]
common = set(a_mnems) & set(b_mnems)

result = {{
    'function_a': {{'address': {addr_a_repr}, 'instruction_count': len(a_insns), 'name': idc.get_func_name({addr_a_int})}},
    'function_b': {{'address': {addr_b_repr}, 'instruction_count': len(b_insns), 'name': idc.get_func_name({addr_b_int})}},
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

        if self.ida.ping():
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
                        },
                        "runtime_module_base": {
                            "type": "string",
                            "description": "Optional runtime module base for ASLR-safe RVA normalization, e.g. '0x7FF712000000'"
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
        return text_result(data)

    def _err(self, msg: str) -> dict:
        return text_error(msg)

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
                        args["address"],
                        args.get("context", ""),
                        args.get("runtime_module_base", ""),
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
    try:
        serve_stdio(server.handle)
    finally:
        server.orchestrator.close()


if __name__ == "__main__":
    main()
