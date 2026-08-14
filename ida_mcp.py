#!/usr/bin/env python3
"""
IDA Pro MCP server for Claude Code.

Connects to IDA Pro 9.x's built-in HTTP server and exposes reverse
engineering operations as MCP tools. Uses IDAPython as the execution
engine — every tool generates a small Python snippet, runs it inside
IDA, and parses the JSON result.

Setup (two options):
  Option A — IDA 9.x auto-starts HTTP server on launch (port 2022).
             Just open your binary in IDA and you're ready.
  Option B — In IDA's Python console run:
             exec(open(r'C:\\path\\to\\ida_server_plugin.py').read())

Add to Claude Code:
    claude mcp add ida -- python "C:\\path\\to\\ida_mcp.py"

Environment variables:
    IDA_MCP_HOST=localhost   (default: localhost)
    IDA_MCP_PORT=2022        (default: 2022)
    IDA_MCP_TIMEOUT=30       (default: 30 seconds)
    IDA_MCP_TOKEN=           (optional Bearer token)
    IDA_PATH=C:\\Program Files\\IDA Professional 9.2   (IDA install dir)
"""

from __future__ import annotations

import json
import os
import re
import sys
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from mco_common import kv_block as _kv, section as _section

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ida"
SERVER_VERSION = "1.0.0"

IDA_PATH = os.environ.get(
    "IDA_PATH",
    r"C:\Program Files\IDA Professional 9.2",
)


# ---------------------------------------------------------------------------
# IDA REST client
# ---------------------------------------------------------------------------

class IDAClient:
    """HTTP client for IDA Pro's REST API.

    Tries several known endpoint shapes in order so this works across
    IDA 8.3, 9.0, 9.1, 9.2 and community HTTP plugins.
    """

    # Endpoint candidates for executing IDAPython code.
    # Each entry: (path, body_template, result_key)
    #   body_template uses {code} placeholder.
    #   result_key: JSON key that holds stdout/result; None = raw text.
    _PY_ENDPOINTS = [
        ("/api/v1/py",          '{"code": {code_json}}',         "output"),
        ("/api/v1/python",      '{"code": {code_json}}',         "output"),
        ("/api/python",         '{"command": {code_json}}',      "output"),
        ("/api/1/exec",         '{"input": {code_json}}',        "result"),
        ("/python",             '{"code": {code_json}}',         "output"),
        ("/exec",               '{"code": {code_json}}',         "output"),
    ]

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        timeout: float | None = None,
        token: str | None = None,
    ) -> None:
        self.host = host or os.environ.get("IDA_MCP_HOST", "localhost")
        self.port = int(port or os.environ.get("IDA_MCP_PORT", "2022"))
        self.timeout = float(timeout or os.environ.get("IDA_MCP_TIMEOUT", "30"))
        self.token = token or os.environ.get("IDA_MCP_TOKEN", "")
        self.base = f"http://{self.host}:{self.port}"
        self._py_ep: tuple[str, str, str | None] | None = None  # discovered endpoint
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _get(self, path: str) -> dict:
        url = self.base + path
        req = urllib.request.Request(url, headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code} {path}: {body[:200]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"IDA not reachable at {self.base}: {e.reason}") from e

    def _post(self, path: str, body: str) -> dict:
        url = self.base + path
        data = body.encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {e.code} {path}: {body_txt[:200]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"IDA not reachable at {self.base}: {e.reason}") from e

    # ------------------------------------------------------------------
    # Python execution
    # ------------------------------------------------------------------

    def _discover_py_endpoint(self) -> tuple[str, str, str | None]:
        """Try each endpoint until one works. Returns (path, body_tmpl, key)."""
        probe = "import json; print(json.dumps({'ok': True}))"
        probe_json = json.dumps(probe)
        for path, tmpl, key in self._PY_ENDPOINTS:
            body = tmpl.replace("{code_json}", probe_json)
            try:
                resp = self._post(path, body)
                # Check we got something sensible
                raw_out = resp.get(key, "") if key else json.dumps(resp)
                if "ok" in raw_out or isinstance(resp, dict):
                    return path, tmpl, key
            except Exception:
                continue
        raise RuntimeError(
            f"Could not find IDAPython execution endpoint at {self.base}.\n"
            "Make sure IDA Pro is open and the HTTP server is running.\n"
            "In IDA Python console: import ida_httpd; ida_httpd.start()"
        )

    def exec_python(self, code: str) -> str:
        """Execute IDAPython code inside IDA. Returns stdout as string."""
        with self._lock:
            if self._py_ep is None:
                self._py_ep = self._discover_py_endpoint()
        path, tmpl, key = self._py_ep
        code_json = json.dumps(textwrap.dedent(code).strip())
        body = tmpl.replace("{code_json}", code_json)
        resp = self._post(path, body)
        if key:
            out = resp.get(key, "")
        else:
            out = json.dumps(resp)
        return out if isinstance(out, str) else json.dumps(out)

    def exec_python_json(self, code: str) -> Any:
        """Execute IDAPython that prints a JSON result. Parses and returns it."""
        raw = self.exec_python(code)
        raw = raw.strip()
        # Find the last complete JSON object/array in the output
        for start in range(len(raw)):
            if raw[start] in ("{", "["):
                try:
                    return json.loads(raw[start:])
                except json.JSONDecodeError:
                    pass
        raise ValueError(f"No JSON in IDA output: {raw[:300]!r}")

    def ping(self) -> bool:
        """Check if IDA is reachable."""
        try:
            result = self.exec_python_json("import json; print(json.dumps({'alive': True}))")
            return result.get("alive") is True
        except Exception:
            return False

    def get_info(self) -> dict:
        """Try the /api/v1/info endpoint, fall back to Python."""
        try:
            return self._get("/api/v1/info")
        except Exception:
            pass
        return self.exec_python_json("""
import idc, idaapi, json, os
info = idaapi.get_inf_structure()
print(json.dumps({
    "input_file": idc.get_input_file_path(),
    "input_md5": idc.retrieve_input_file_md5().hex() if hasattr(idc, 'retrieve_input_file_md5') else '',
    "min_ea": hex(idc.get_inf_attr(idc.INF_MIN_EA)),
    "max_ea": hex(idc.get_inf_attr(idc.INF_MAX_EA)),
    "entry_point": hex(idc.get_inf_attr(idc.INF_START_IP)),
    "image_base": hex(idaapi.get_imagebase()),
    "processor": idc.get_inf_attr(idc.INF_PROCNAME) if hasattr(idc, 'INF_PROCNAME') else idaapi.inf_get_procname(),
    "bits": 64 if info.is_64bit() else 32,
    "file_type": idc.get_file_type_name(),
    "is_dll": bool(info.is_dll()),
}))
""")


# Singleton client
_CLIENT: IDAClient | None = None


def _client() -> IDAClient:
    global _CLIENT
    if _CLIENT is None:
        _CLIENT = IDAClient()
    return _CLIENT


# ---------------------------------------------------------------------------
# Output formatting helpers
# ---------------------------------------------------------------------------

def _require_ida() -> str | None:
    if not _client().ping():
        return (
            "ERROR: IDA Pro not reachable at "
            f"{_client().base}.\n"
            "Make sure IDA is open with a binary loaded and the HTTP server is active."
        )
    return None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def tool_status() -> str:
    c = _client()
    reachable = c.ping()
    if not reachable:
        return _section("IDA STATUS", f"NOT CONNECTED\nIDA not reachable at {c.base}\nOpen IDA Pro and load a binary.")
    try:
        info = c.get_info()
        pairs = [
            ("server", c.base),
            ("file", info.get("input_file", "?")),
            ("bits", str(info.get("bits", "?"))),
            ("processor", info.get("processor", "?")),
            ("image_base", info.get("image_base", "?")),
            ("entry_point", info.get("entry_point", "?")),
            ("min_ea", info.get("min_ea", "?")),
            ("max_ea", info.get("max_ea", "?")),
        ]
        if info.get("input_md5"):
            pairs.append(("md5", info["input_md5"]))
    except Exception as e:
        pairs = [("server", c.base), ("error", str(e))]
    return _section("IDA STATUS", _kv(pairs))


def tool_info() -> str:
    err = _require_ida()
    if err:
        return err
    try:
        info = _client().get_info()
        return _section("BINARY INFO", _kv([(k, v) for k, v in info.items()]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_functions(offset: int = 0, limit: int = 100, pattern: str = "") -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idautils, idc, json
funcs = []
pattern = {json.dumps(pattern)}
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if pattern and pattern.lower() not in name.lower():
        continue
    funcs.append({{"ea": hex(ea), "name": name,
        "size": idc.get_func_attr(ea, idc.FUNCATTR_END) - ea}})
page = funcs[{offset}:{offset}+{limit}]
print(json.dumps({{"total": len(funcs), "offset": {offset}, "functions": page}}))
""")
        total = result.get("total", 0)
        funcs = result.get("functions", [])
        lines = [f"total={total}  showing [{offset}:{offset+len(funcs)}]"]
        for f in funcs:
            lines.append(f"  {f['ea']}  {f['name']}  ({f['size']} bytes)")
        return _section("FUNCTIONS", "\n".join(lines))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_segments() -> str:
    err = _require_ida()
    if err:
        return err
    try:
        segs = _client().exec_python_json("""
import idautils, idc, idaapi, json
segs = []
for seg in idautils.Segments():
    s = idaapi.getseg(seg)
    segs.append({
        "start": hex(seg), "end": hex(idc.get_segm_end(seg)),
        "name": idc.get_segm_name(seg), "class": idc.get_segm_class(seg),
        "perm": s.perm if s else 0,
        "size": idc.get_segm_end(seg) - seg,
    })
print(json.dumps(segs))
""")
        lines = ["start            end              name        class   size"]
        for s in segs:
            perm = s.get("perm", 0)
            perm_str = ("r" if perm & 4 else "-") + ("w" if perm & 2 else "-") + ("x" if perm & 1 else "-")
            lines.append(
                f"  {s['start']:<16}  {s['end']:<16}  {s['name']:<10}  "
                f"{s['class']:<6}  {s['size']:#x}  {perm_str}"
            )
        return _section("SEGMENTS", "\n".join(lines))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_imports(module: str = "") -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idaapi, json
result = {{}}
nimps = idaapi.get_import_module_qty()
filter_mod = {json.dumps(module.lower())}
for i in range(nimps):
    mod = idaapi.get_import_module_name(i)
    if not mod:
        continue
    if filter_mod and filter_mod not in mod.lower():
        continue
    entries = []
    def cb(ea, name, ordinal):
        entries.append({{"ea": hex(ea), "name": name or "", "ordinal": ordinal}})
        return True
    idaapi.enum_import_names(i, cb)
    result[mod] = entries
print(json.dumps(result))
""")
        lines = []
        total = 0
        for dll, entries in result.items():
            lines.append(f"\n  [{dll}]")
            for e in entries:
                total += 1
                name = e["name"] or f"ord_{e['ordinal']}"
                lines.append(f"    {e['ea']}  {name}")
        return _section(f"IMPORTS (total {total})", "\n".join(lines) or "(none)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_exports() -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json("""
import idautils, json
exports = [{"ea": hex(ea), "ordinal": ord_, "name": name}
           for (_, ord_, ea, name) in idautils.Entries()]
print(json.dumps(exports))
""")
        lines = [f"  {e['ea']}  ord={e['ordinal']}  {e['name']}" for e in result]
        return _section(f"EXPORTS ({len(result)})", "\n".join(lines) or "(none)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_strings(min_len: int = 4, limit: int = 200) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idautils, idc, json
strings = []
sc = idautils.Strings()
sc.setup(minlen={min_len})
for s in sc:
    strings.append({{"ea": hex(s.ea), "length": s.length, "string": str(s)}})
    if len(strings) >= {limit}:
        break
print(json.dumps({{"count": len(strings), "strings": strings}}))
""")
        strs = result.get("strings", [])
        lines = [f"  {s['ea']}  ({s['length']}b)  {s['string']!r}" for s in strs]
        return _section(f"STRINGS ({result.get('count', len(strs))})", "\n".join(lines) or "(none)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_names(pattern: str = "", limit: int = 200) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idautils, idc, json
names = []
pat = {json.dumps(pattern.lower())}
for ea, name in idautils.Names():
    if pat and pat not in name.lower():
        continue
    names.append({{"ea": hex(ea), "name": name}})
    if len(names) >= {limit}:
        break
print(json.dumps(names))
""")
        lines = [f"  {n['ea']}  {n['name']}" for n in result]
        return _section(f"NAMES ({len(result)})", "\n".join(lines) or "(none)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_disassemble(address: str, count: int = 20, function: bool = False) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        if function:
            result = _client().exec_python_json(f"""
import idc, idautils, idaapi, json
ea = {_parse_addr(address)}
func = idaapi.get_func(ea)
if not func:
    print(json.dumps({{"error": "no function at address"}}))
else:
    lines = []
    for insn_ea in idautils.FuncItems(func.start_ea):
        disasm = idc.generate_disasm_line(insn_ea, 0)
        lines.append({{"ea": hex(insn_ea), "disasm": disasm}})
    print(json.dumps({{"function": idc.get_func_name(func.start_ea), "lines": lines}}))
""")
            if "error" in result:
                return f"ERROR: {result['error']}"
            lines = [f"  {l['ea']}  {l['disasm']}" for l in result.get("lines", [])]
            return _section(f"FUNCTION {result.get('function', address)}", "\n".join(lines))
        else:
            result = _client().exec_python_json(f"""
import idc, json
ea = {_parse_addr(address)}
lines = []
current = ea
for _ in range({count}):
    disasm = idc.generate_disasm_line(current, 0)
    size = idc.get_item_size(current)
    lines.append({{"ea": hex(current), "disasm": disasm, "size": size}})
    current = idc.next_head(current)
    if current == idc.BADADDR:
        break
print(json.dumps(lines))
""")
            lines = [f"  {l['ea']}  {l['disasm']}" for l in result]
            return _section(f"DISASM @ {address} ({count} insns)", "\n".join(lines))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_decompile(address: str) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idaapi, json
try:
    import ida_hexrays
    ea = {_parse_addr(address)}
    cf = ida_hexrays.decompile(ea)
    if cf:
        print(json.dumps({{"success": True, "pseudocode": str(cf), "function": cf.entry_ea}}))
    else:
        print(json.dumps({{"success": False, "error": "decompile returned None"}}))
except Exception as e:
    print(json.dumps({{"success": False, "error": str(e)}}))
""")
        if not result.get("success"):
            return f"ERROR: {result.get('error', 'decompile failed')}"
        func_ea = result.get("function")
        pseudo = result.get("pseudocode", "")
        title = f"DECOMPILE @ {address}"
        if func_ea:
            title += f" (ea={hex(func_ea) if isinstance(func_ea, int) else func_ea})"
        return _section(title, pseudo)
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_xrefs_to(address: str, limit: int = 50) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idautils, idc, json
ea = {_parse_addr(address)}
refs = []
for ref in idautils.XrefsTo(ea):
    refs.append({{"from_ea": hex(ref.frm), "type": ref.type,
        "from_name": idc.get_func_name(ref.frm) or hex(ref.frm)}})
    if len(refs) >= {limit}:
        break
print(json.dumps(refs))
""")
        lines = [f"  {r['from_ea']}  [{r['type']}]  {r['from_name']}" for r in result]
        return _section(f"XREFS TO {address} ({len(result)})", "\n".join(lines) or "(none)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_xrefs_from(address: str, limit: int = 50) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idautils, idc, json
ea = {_parse_addr(address)}
refs = []
for ref in idautils.XrefsFrom(ea):
    refs.append({{"to_ea": hex(ref.to), "type": ref.type,
        "to_name": idc.get_name(ref.to) or hex(ref.to)}})
    if len(refs) >= {limit}:
        break
print(json.dumps(refs))
""")
        lines = [f"  {r['to_ea']}  [{r['type']}]  {r['to_name']}" for r in result]
        return _section(f"XREFS FROM {address} ({len(result)})", "\n".join(lines) or "(none)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_rename(address: str, name: str) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idc, json
ea = {_parse_addr(address)}
old = idc.get_name(ea) or hex(ea)
ok = idc.set_name(ea, {json.dumps(name)}, idc.SN_NOCHECK | idc.SN_NOWARN)
print(json.dumps({{"ok": bool(ok), "ea": hex(ea), "old": old, "new": {json.dumps(name)}}}))
""")
        return _section(f"RENAME {address}", _kv([
            ("address", result.get("ea", address)),
            ("old_name", result.get("old", "?")),
            ("new_name", result.get("new", name)),
            ("success", str(result.get("ok", False))),
        ]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_comment(address: str, text: str, kind: str = "regular") -> str:
    """Set comment at address. kind: regular|repeatable|anterior|posterior"""
    err = _require_ida()
    if err:
        return err
    try:
        kind_map = {
            "regular": "set_cmt(ea, text, 0)",
            "repeatable": "set_cmt(ea, text, 1)",
            "anterior": "set_func_cmt(ea, text, 0)",
            "posterior": "set_func_cmt(ea, text, 1)",
        }
        call = kind_map.get(kind, "set_cmt(ea, text, 0)")
        result = _client().exec_python_json(f"""
import idc, json
ea = {_parse_addr(address)}
text = {json.dumps(text)}
idc.{call}
print(json.dumps({{"ok": True, "ea": hex(ea), "kind": {json.dumps(kind)}}}))
""")
        return _section(f"COMMENT @ {address}", _kv([("kind", kind), ("text", text), ("ok", str(result.get("ok")))]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_set_type(address: str, type_str: str) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idc, idaapi, json
ea = {_parse_addr(address)}
tinfo = idaapi.tinfo_t()
ok = idaapi.parse_decl(tinfo, None, {json.dumps(type_str + ";")}, idaapi.PT_SIL)
if ok:
    applied = idaapi.apply_tinfo(ea, tinfo, idaapi.TINFO_DEFINITE)
else:
    applied = False
    ok2 = idc.SetType(ea, {json.dumps(type_str)})
    applied = bool(ok2)
print(json.dumps({{"ok": applied, "ea": hex(ea), "type": {json.dumps(type_str)}}}))
""")
        return _section(f"SET TYPE @ {address}", _kv([
            ("address", result.get("ea", address)),
            ("type", type_str),
            ("success", str(result.get("ok"))),
        ]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_get_type(address: str) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idc, idaapi, json
ea = {_parse_addr(address)}
tinfo = idaapi.tinfo_t()
if idaapi.get_tinfo(tinfo, ea):
    type_str = str(tinfo)
else:
    type_str = idc.get_type(ea) or ''
name = idc.get_name(ea) or hex(ea)
print(json.dumps({{"ea": hex(ea), "name": name, "type": type_str}}))
""")
        return _section(f"TYPE @ {address}", _kv([
            ("address", result.get("ea", address)),
            ("name", result.get("name", "?")),
            ("type", result.get("type", "(none)")),
        ]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_read_bytes(address: str, size: int = 64) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idc, idaapi, json
ea = {_parse_addr(address)}
size = {size}
data = idaapi.get_bytes(ea, size)
if data:
    hex_dump = []
    ascii_dump = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{{b:02x}}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        hex_dump.append(f'{{ea+i:016x}}  {{hex_part:<47}}  {{ascii_part}}')
    print(json.dumps({{"ok": True, "dump": chr(10).join(hex_dump), "raw_hex": data.hex()}}))
else:
    print(json.dumps({{"ok": False, "error": "read failed"}}))
""")
        if not result.get("ok"):
            return f"ERROR: {result.get('error', 'read failed')}"
        return _section(f"BYTES @ {address} ({size} bytes)", result.get("dump", ""))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_search(pattern: str, kind: str = "bytes", limit: int = 20) -> str:
    """Search for bytes or strings. kind: bytes|string|unicode"""
    err = _require_ida()
    if err:
        return err
    try:
        if kind == "bytes":
            result = _client().exec_python_json(f"""
import idc, idaapi, json
pattern_str = {json.dumps(pattern)}
# Parse hex pattern like "48 89 ?? 24" or "E8 ?? ?? ?? ??"
parts = pattern_str.split()
byte_seq = bytes(int(p, 16) for p in parts if p != '??')
mask = bytes(0xff if p != '??' else 0x00 for p in parts)

hits = []
start = idc.get_inf_attr(idc.INF_MIN_EA)
end = idc.get_inf_attr(idc.INF_MAX_EA)
ea = idaapi.find_binary(start, end, pattern_str.replace('??', '?'), 0x10, idc.SEARCH_DOWN)
while ea != idc.BADADDR and len(hits) < {limit}:
    hits.append(hex(ea))
    ea = idaapi.find_binary(ea + 1, end, pattern_str.replace('??', '?'), 0x10, idc.SEARCH_DOWN)
print(json.dumps({{"hits": hits, "count": len(hits)}}))
""")
        else:  # string or unicode
            result = _client().exec_python_json(f"""
import idc, idautils, json
search = {json.dumps(pattern.lower())}
kind = {json.dumps(kind)}
hits = []
sc = idautils.Strings()
sc.setup(minlen=1)
for s in sc:
    if search in str(s).lower():
        hits.append({{"ea": hex(s.ea), "string": str(s), "length": s.length}})
        if len(hits) >= {limit}:
            break
print(json.dumps({{"hits": hits, "count": len(hits)}}))
""")
        hits = result.get("hits", [])
        if isinstance(hits, list) and hits and isinstance(hits[0], str):
            lines = [f"  {h}" for h in hits]
        else:
            lines = [f"  {h.get('ea', '?')}  {h.get('string', '')!r}" for h in hits]
        count = result.get("count", len(hits))
        return _section(f"SEARCH {kind} '{pattern}' ({count} hits)", "\n".join(lines) or "(no hits)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_run_script(code: str) -> str:
    """Execute raw IDAPython code inside IDA."""
    err = _require_ida()
    if err:
        return err
    try:
        out = _client().exec_python(code)
        return _section("IDAPYTHON OUTPUT", out.strip() or "(no output)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_analyze_function(address: str) -> str:
    """Deep function analysis: disasm + decompile + xrefs + calls."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idaapi, idautils, idc, json
ea = {_parse_addr(address)}
func = idaapi.get_func(ea)
if not func:
    print(json.dumps({{"error": "no function"}}))
else:
    name = idc.get_func_name(func.start_ea)
    size = func.size()
    # Collect instructions, calls, strings refs
    calls = []
    strings = []
    api_calls = []
    for item_ea in idautils.FuncItems(func.start_ea):
        disasm = idc.generate_disasm_line(item_ea, 0)
        if 'call' in disasm.lower():
            target = idc.get_operand_value(item_ea, 0)
            target_name = idc.get_name(target) or hex(target)
            calls.append({{"ea": hex(item_ea), "target": target_name, "disasm": disasm}})
        # String refs
        for ref in idautils.DataRefsFrom(item_ea):
            s = idc.get_strlit_contents(ref, -1, 0)
            if s:
                strings.append({{"ea": hex(ref), "value": s.decode('utf-8', 'replace')[:80]}})
    # xrefs to this function
    xrefs_in = [{{"from": hex(r.frm), "name": idc.get_func_name(r.frm) or hex(r.frm)}}
                for r in list(idautils.XrefsTo(func.start_ea))[:20]]
    print(json.dumps({{
        "name": name,
        "start": hex(func.start_ea),
        "end": hex(func.end_ea),
        "size": size,
        "calls": calls[:30],
        "string_refs": strings[:20],
        "xrefs_in": xrefs_in,
        "is_lib": bool(func.flags & 4),
        "is_thunk": bool(func.flags & 128),
    }}))
""")
        if "error" in result:
            return f"ERROR: {result['error']}"
        parts = []
        parts.append(_section("FUNCTION INFO", _kv([
            ("name", result.get("name", "?")),
            ("start", result.get("start", "?")),
            ("end", result.get("end", "?")),
            ("size", f"{result.get('size', 0)} bytes"),
            ("is_lib", str(result.get("is_lib", False))),
            ("is_thunk", str(result.get("is_thunk", False))),
        ])))
        calls = result.get("calls", [])
        if calls:
            call_lines = [f"  {c['ea']}  {c['disasm']}" for c in calls]
            parts.append(_section(f"CALLS ({len(calls)})", "\n".join(call_lines)))
        strings = result.get("string_refs", [])
        if strings:
            str_lines = [f"  {s['ea']}  {s['value']!r}" for s in strings]
            parts.append(_section(f"STRING REFS ({len(strings)})", "\n".join(str_lines)))
        xrefs = result.get("xrefs_in", [])
        if xrefs:
            x_lines = [f"  {x['from']}  {x['name']}" for x in xrefs]
            parts.append(_section(f"CALLED FROM ({len(xrefs)})", "\n".join(x_lines)))
        # Try decompile
        try:
            decompiled = tool_decompile(result.get("start", address))
            parts.append(decompiled)
        except Exception:
            pass
        return "\n\n".join(parts)
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_entry_points() -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json("""
import idautils, idc, json
entries = [{"ordinal": ord_, "ea": hex(ea), "name": name}
           for (_, ord_, ea, name) in idautils.Entries()]
# Also add start_ea
start = idc.get_inf_attr(idc.INF_START_IP)
if start != idc.BADADDR:
    entries.insert(0, {"ordinal": -1, "ea": hex(start), "name": "start"})
print(json.dumps(entries))
""")
        lines = [f"  {e['ea']}  ord={e['ordinal']}  {e['name']}" for e in result]
        return _section(f"ENTRY POINTS ({len(result)})", "\n".join(lines) or "(none)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_struct(name: str) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idc, idaapi, json
name = {json.dumps(name)}
sid = idc.get_struc_id(name)
if sid == idc.BADADDR:
    print(json.dumps({{"error": f"struct not found: {{name}}"}}))
else:
    s = idaapi.get_struc(sid)
    members = []
    for i in range(s.memqty):
        m = s.get_member(i)
        mname = idc.get_member_name(sid, m.soff)
        mtype = idc.get_member_tinfo(sid, m.soff)
        members.append({{"offset": m.soff, "name": mname, "size": m.eoff - m.soff}})
    print(json.dumps({{"name": name, "size": idc.get_struc_size(sid), "members": members}}))
""")
        if "error" in result:
            return f"ERROR: {result['error']}"
        lines = [f"  +{m['offset']:#06x}  {m['name']:<30}  ({m['size']} bytes)" for m in result.get("members", [])]
        return _section(f"STRUCT {result.get('name')} (size={result.get('size')})",
                       "\n".join(lines) or "(no members)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_make_function(address: str) -> str:
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idc, idaapi, json
ea = {_parse_addr(address)}
# Try to create function
ok = idc.add_func(ea)
if ok:
    name = idc.get_func_name(ea)
    size = idc.get_func_attr(ea, idc.FUNCATTR_END) - ea
    print(json.dumps({{"ok": True, "ea": hex(ea), "name": name, "size": size}}))
else:
    # Maybe already a function
    func = idaapi.get_func(ea)
    if func:
        print(json.dumps({{"ok": True, "already": True, "ea": hex(func.start_ea),
            "name": idc.get_func_name(func.start_ea)}}))
    else:
        print(json.dumps({{"ok": False, "ea": hex(ea)}}))
""")
        return _section(f"MAKE FUNCTION @ {address}", _kv([
            ("address", result.get("ea", address)),
            ("name", result.get("name", "?")),
            ("size", str(result.get("size", "?"))),
            ("success", str(result.get("ok", False))),
            ("already_existed", str(result.get("already", False))),
        ]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_apply_signature(sig_file: str) -> str:
    """Apply a FLIRT signature file (.sig) to the database."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idc, idaapi, json
sig = {json.dumps(sig_file)}
# Load sig file
ok = idaapi.plan_and_wait(0, 0xffffffffffffffff)  # reanalyze
if idc.ApplySig(sig):
    print(json.dumps({{"ok": True, "sig": sig}}))
else:
    print(json.dumps({{"ok": False, "sig": sig, "error": "ApplySig failed — check path"}}))
""")
        if not result.get("ok"):
            return f"ERROR: {result.get('error', 'failed')}"
        return _section("APPLY SIGNATURE", _kv([("file", sig_file), ("ok", "true")]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_find_crypto() -> str:
    """Scan for crypto algorithm indicators (constants, xor patterns)."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json("""
import idautils, idc, idaapi, json

# Known crypto constants (hash init vectors, AES S-box markers)
CRYPTO_CONSTS = {
    0x67452301: "MD5/SHA1 init H0",
    0xEFCDAB89: "MD5/SHA1 init H1",
    0x98BADCFE: "MD5/SHA1 init H2",
    0x10325476: "MD5/SHA1 init H3",
    0x6A09E667: "SHA-256 init H0",
    0xBB67AE85: "SHA-256 init H1",
    0x3C6EF372: "SHA-256 init H2",
    0xA54FF53A: "SHA-256 init H3",
    0x9B05688C: "SHA-256 init H4",
    0x1F83D9AB: "SHA-256 init H5",
    0x5BE0CD19: "SHA-256 init H6",
    0x52096AD5: "AES S-box row 0",
    0x30000000: "RC4 KSA marker (approx)",
    0x61C88647: "AES MixColumns constant",
    0x9E3779B9: "TEA/XTEA delta constant",
    0x61C88647: "AES round key constant",
}


hits = []
for seg_ea in idautils.Segments():
    for ea in idautils.Items(seg_ea, idc.get_segm_end(seg_ea)):
        val = idc.get_wide_dword(ea)
        if val in CRYPTO_CONSTS:
            hits.append({"ea": hex(ea), "value": hex(val), "meaning": CRYPTO_CONSTS[val]})
        # XOR patterns (detect repeated XOR operations)
        disasm = idc.generate_disasm_line(ea, 0)
        if disasm and 'xor' in disasm.lower() and 'eax, eax' not in disasm and 'xor eax, eax' not in disasm:
            if any(c in disasm for c in ['0x', 'dword', 'qword']):
                hits.append({"ea": hex(ea), "value": disasm, "meaning": "XOR pattern (possible crypto)"})
        if len(hits) > 100:
            break
    if len(hits) > 100:
        break

print(json.dumps({"hits": hits[:100], "count": len(hits)}))
""")
        hits = result.get("hits", [])
        lines = [f"  {h['ea']}  {h['value']:<20}  {h['meaning']}" for h in hits]
        return _section(f"CRYPTO INDICATORS ({result.get('count', len(hits))})",
                       "\n".join(lines) or "(none found)")
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_scan_bossix() -> str:
    """Scan for bossix techniques in imports and code."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json("""
import idaapi, idautils, idc, json

BOSSIX_APIS = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugString", "FindWindow", "CreateToolhelp32Snapshot",
    "ZwSetInformationThread", "NtSetInformationThread", "CloseHandle",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
    "timeGetTime", "rdtsc", "NtQuerySystemTime", "SetUnhandledExceptionFilter",
    "UnhandledExceptionFilter", "DebugBreak", "DebugBreakProcess",
    "NtQueryObject", "NtQueryPerformanceCounter",
]

BOSSIX_BYTES = {
    "RDTSC": "0F 31",
    "INT3": "CC",
    "INT 3": "CD 03",
    "CPUID check": "0F A2",
}

findings = {"imported_apis": [], "byte_patterns": [], "string_indicators": []}

# Check imports
nimps = idaapi.get_import_module_qty()
for i in range(nimps):
    def cb(ea, name, ordinal):
        if name and any(api.lower() in name.lower() for api in BOSSIX_APIS):
            findings["imported_apis"].append({"ea": hex(ea), "name": name})
        return True
    idaapi.enum_import_names(i, cb)

# Check strings for debugger-related keywords
sc = idautils.Strings()
sc.setup(minlen=4)
debug_keywords = ["debugger", "debug", "ollydbg", "x64dbg", "ida", "windbg", "cheat engine"]
for s in sc:
    sv = str(s).lower()
    if any(kw in sv for kw in debug_keywords):
        findings["string_indicators"].append({"ea": hex(s.ea), "string": str(s)})
    if len(findings["string_indicators"]) > 20:
        break

print(json.dumps(findings))
""")
        parts = []
        apis = result.get("imported_apis", [])
        if apis:
            lines = [f"  {a['ea']}  {a['name']}" for a in apis]
            parts.append(_section(f"ANTI-DEBUG IMPORTS ({len(apis)})", "\n".join(lines)))
        strs = result.get("string_indicators", [])
        if strs:
            lines = [f"  {s['ea']}  {s['string']!r}" for s in strs]
            parts.append(_section(f"SUSPICIOUS STRINGS ({len(strs)})", "\n".join(lines)))
        if not parts:
            parts.append(_section("ANTI-DEBUG SCAN", "No obvious anti-debug indicators found."))
        return "\n\n".join(parts)
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def _friendly_error(raw: str) -> str:
    """Convert raw exception strings into actionable messages."""
    low = raw.lower()
    if "not connected" in low or "connection refused" in low or "not reachable" in low:
        return (
            "IDA Pro is not running or HTTP server not started. "
            "Run ida_server_plugin.py inside IDA first, or use IDA 9.x "
            "which auto-starts the HTTP server on port 2022."
        )
    m = re.search(r"name '([^']+)' is not defined", raw)
    if m:
        return (
            f"IDAPython module not available: '{m.group(1)}' is not defined. "
            "The IDA server may be running outside IDA context."
        )
    return raw


def tool_diff_functions(addr1: str, addr2: str) -> str:
    """Compare two functions side-by-side: disasm, size, instruction count."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idaapi, idautils, idc, json

def collect(ea):
    func = idaapi.get_func(ea)
    if not func:
        return None
    lines = []
    for insn_ea in idautils.FuncItems(func.start_ea):
        lines.append(idc.generate_disasm_line(insn_ea, 0))
    return {{
        "name": idc.get_func_name(func.start_ea),
        "start": hex(func.start_ea),
        "size": func.size(),
        "insn_count": len(lines),
        "lines": lines,
    }}

f1 = collect({_parse_addr(addr1)})
f2 = collect({_parse_addr(addr2)})
print(json.dumps({{"f1": f1, "f2": f2}}))
""")
        f1 = result.get("f1")
        f2 = result.get("f2")
        if not f1:
            return f"ERROR: No function at {addr1}"
        if not f2:
            return f"ERROR: No function at {addr2}"

        parts = [_section("FUNCTION DIFF SUMMARY", _kv([
            ("func1", f"{f1['name']} @ {f1['start']} ({f1['size']} bytes, {f1['insn_count']} insns)"),
            ("func2", f"{f2['name']} @ {f2['start']} ({f2['size']} bytes, {f2['insn_count']} insns)"),
            ("size_delta", f"{f2['size'] - f1['size']:+d} bytes"),
            ("insn_delta", f"{f2['insn_count'] - f1['insn_count']:+d} instructions"),
        ]))]

        lines1 = f1["lines"]
        lines2 = f2["lines"]
        max_rows = min(max(len(lines1), len(lines2)), 60)
        match = mismatch = 0
        diff_lines = []
        for i in range(max_rows):
            l1 = lines1[i] if i < len(lines1) else "<end>"
            l2 = lines2[i] if i < len(lines2) else "<end>"
            m1 = l1.split()[0] if l1.split() else ""
            m2 = l2.split()[0] if l2.split() else ""
            tag = "=" if m1 == m2 else "!"
            match += tag == "="
            mismatch += tag == "!"
            diff_lines.append(f"  {tag}  {l1:<45}  |  {l2}")
        parts.append(_section(
            f"SIDE-BY-SIDE (= match, ! differ;  match={match}  differ={mismatch})",
            "\n".join(diff_lines)
        ))
        return "\n\n".join(parts)
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_call_tree(address: str, depth: int = 3) -> str:
    """Build a recursive call tree from a function up to `depth` levels deep."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idaapi, idautils, idc, json

def build_tree(ea, depth, visited):
    func = idaapi.get_func(ea)
    if func:
        key = func.start_ea
        name = idc.get_func_name(func.start_ea)
        start_hex = hex(func.start_ea)
    else:
        key = ea
        name = idc.get_name(ea) or hex(ea)
        start_hex = hex(ea)
    node = {{"ea": start_hex, "name": name, "children": []}}
    if depth <= 0 or key in visited:
        node["truncated"] = True
        return node
    visited = visited | {{key}}
    callees = set()
    if func:
        for item_ea in idautils.FuncItems(func.start_ea):
            disasm = idc.generate_disasm_line(item_ea, 0)
            if disasm and 'call' in disasm.lower():
                target = idc.get_operand_value(item_ea, 0)
                if target and target != idc.BADADDR:
                    callee = idaapi.get_func(target)
                    if callee and callee.start_ea not in visited:
                        callees.add(callee.start_ea)
    for callee_ea in list(callees)[:10]:
        node["children"].append(build_tree(callee_ea, depth - 1, visited))
    return node

root_ea = {_parse_addr(address)}
tree = build_tree(root_ea, {depth}, set())
print(json.dumps(tree))
""")

        def _render(node: dict, indent: int = 0) -> list[str]:
            prefix = "  " * indent + ("|- " if indent else "")
            suffix = " [...]" if node.get("truncated") else ""
            out = [f"{prefix}{node['name']} @ {node['ea']}{suffix}"]
            for child in node.get("children", []):
                out.extend(_render(child, indent + 1))
            return out

        lines = _render(result)
        return _section(f"CALL TREE @ {address} (depth={depth})", "\n".join(lines))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_patch_bytes(address: str, hex_bytes: str) -> str:
    """Patch bytes in IDA database (not the file) using idc.patch_byte().
    hex_bytes: space-separated or solid hex string, e.g. '90 90 90' or '909090'."""
    err = _require_ida()
    if err:
        return err
    try:
        clean = hex_bytes.replace(" ", "").replace("0x", "").replace("0X", "")
        if not clean:
            return "ERROR: hex_bytes is empty"
        if len(clean) % 2 != 0:
            return "ERROR: hex_bytes must have an even number of hex digits"
        byte_list = [int(clean[i:i+2], 16) for i in range(0, len(clean), 2)]
        expected_hex = "".join(f"{b:02x}" for b in byte_list)
        result = _client().exec_python_json(f"""
import idc, idaapi, json
ea = {_parse_addr(address)}
byte_list = {byte_list!r}
orig = idaapi.get_bytes(ea, len(byte_list))
orig_hex = orig.hex() if orig else ''
for i, b in enumerate(byte_list):
    idc.patch_byte(ea + i, b)
verify = idaapi.get_bytes(ea, len(byte_list))
verify_hex = verify.hex() if verify else ''
print(json.dumps({{
    "ok": verify_hex == {json.dumps(expected_hex)},
    "ea": hex(ea),
    "orig_hex": orig_hex,
    "patched_hex": verify_hex,
    "count": len(byte_list),
}}))
""")
        return _section(f"PATCH @ {address}", _kv([
            ("address", result.get("ea", address)),
            ("bytes_written", str(result.get("count", 0))),
            ("original", result.get("orig_hex", "?")),
            ("patched", result.get("patched_hex", "?")),
            ("success", str(result.get("ok", False))),
        ]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_list_patches() -> str:
    """List all patches applied to the IDA database via idc.next_patch_ea() iteration."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json("""
import idc, idaapi, json

patches = []
try:
    next_fn = idc.next_patch_ea
except AttributeError:
    next_fn = getattr(idc, 'nextpatch', None)

if next_fn is not None:
    ea = next_fn(0)
    while ea != idc.BADADDR:
        orig = idc.get_original_byte(ea)
        patched = idc.get_wide_byte(ea)
        patches.append({"ea": hex(ea), "orig": "%02x" % orig, "patched": "%02x" % patched})
        ea = next_fn(ea + 1)

print(json.dumps({"patches": patches, "count": len(patches)}))
""")
        patches = result.get("patches", [])
        if not patches:
            return _section("PATCHES", "No patches applied to this database.")
        lines = [f"  {p['ea']}  orig={p['orig']}  new={p['patched']}" for p in patches]
        return _section(f"PATCHES ({len(patches)} bytes modified)", "\n".join(lines))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_export_idb_info() -> str:
    """Export comprehensive IDA database summary: file, hashes, and count statistics."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json("""
import idc, idaapi, idautils, json

info_struct = idaapi.get_inf_structure()
func_count = len(list(idautils.Functions()))
seg_count = len(list(idautils.Segments()))
entry_count = len(list(idautils.Entries()))
nim = idaapi.get_import_module_qty()

sc = idautils.Strings()
sc.setup(minlen=4)
string_count = sum(1 for _ in sc)

try:
    md5_hex = idc.retrieve_input_file_md5().hex()
except Exception:
    md5_hex = ""
try:
    sha256_hex = idc.retrieve_input_file_sha256().hex()
except Exception:
    sha256_hex = ""

patch_count = 0
try:
    next_fn = idc.next_patch_ea
except AttributeError:
    next_fn = getattr(idc, 'nextpatch', None)
if next_fn:
    pea = next_fn(0)
    while pea != idc.BADADDR:
        patch_count += 1
        pea = next_fn(pea + 1)

print(json.dumps({
    "input_file": idc.get_input_file_path(),
    "md5": md5_hex,
    "sha256": sha256_hex,
    "image_base": hex(idaapi.get_imagebase()),
    "bits": 64 if info_struct.is_64bit() else 32,
    "is_dll": bool(info_struct.is_dll()),
    "min_ea": hex(idc.get_inf_attr(idc.INF_MIN_EA)),
    "max_ea": hex(idc.get_inf_attr(idc.INF_MAX_EA)),
    "entry_count": entry_count,
    "function_count": func_count,
    "segment_count": seg_count,
    "string_count": string_count,
    "import_module_count": nim,
    "patch_count": patch_count,
}))
""")
        return _section("IDB EXPORT INFO", _kv([
            ("input_file",      result.get("input_file", "?")),
            ("md5",             result.get("md5") or "(unavailable)"),
            ("sha256",          result.get("sha256") or "(unavailable)"),
            ("image_base",      result.get("image_base", "?")),
            ("bits",            str(result.get("bits", "?"))),
            ("is_dll",          str(result.get("is_dll", False))),
            ("address_range",   f"{result.get('min_ea','?')} - {result.get('max_ea','?')}"),
            ("entry_points",    str(result.get("entry_count", 0))),
            ("functions",       str(result.get("function_count", 0))),
            ("segments",        str(result.get("segment_count", 0))),
            ("strings",         str(result.get("string_count", 0))),
            ("import_modules",  str(result.get("import_module_count", 0))),
            ("patches_applied", str(result.get("patch_count", 0))),
        ]))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_find_string_refs(pattern: str) -> str:
    """Find strings matching a regex pattern; return string value, address, and xref callers."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idautils, idc, idaapi, re, json
pat = re.compile({json.dumps(pattern)}, re.IGNORECASE)
hits = []
sc = idautils.Strings()
sc.setup(minlen=3)
for s in sc:
    sv = str(s)
    if pat.search(sv):
        refs = []
        for xref in idautils.XrefsTo(s.ea):
            func = idaapi.get_func(xref.frm)
            fn = idc.get_func_name(func.start_ea) if func else hex(xref.frm)
            refs.append({{"from_ea": hex(xref.frm), "func": fn}})
        hits.append({{"ea": hex(s.ea), "string": sv, "xrefs": refs[:20]}})
        if len(hits) >= 50:
            break
print(json.dumps({{"hits": hits, "count": len(hits)}}))
""")
        hits = result.get("hits", [])
        if not hits:
            return _section(f"STRING REFS /{pattern}/", "No matching strings found.")
        blocks = []
        for h in hits:
            xref_lines = [f"    <- {x['from_ea']}  {x['func']}" for x in h.get("xrefs", [])]
            xref_text = "\n".join(xref_lines) if xref_lines else "    (no xrefs)"
            blocks.append(f"  {h['ea']}  {h['string']!r}\n{xref_text}")
        return _section(f"STRING REFS /{pattern}/ ({len(hits)} matches)", "\n\n".join(blocks))
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def tool_get_pseudocode_all_functions(limit: int = 20) -> str:
    """Decompile up to `limit` functions. Returns list of {name, address, pseudocode}."""
    err = _require_ida()
    if err:
        return err
    try:
        result = _client().exec_python_json(f"""
import idautils, idc, idaapi, json
try:
    import ida_hexrays
    has_hexrays = True
except ImportError:
    has_hexrays = False

results = []
if has_hexrays:
    for ea in list(idautils.Functions())[:{limit}]:
        name = idc.get_func_name(ea)
        try:
            cf = ida_hexrays.decompile(ea)
            pseudo = str(cf) if cf else None
        except Exception as ex:
            pseudo = "<error: " + str(ex) + ">"
        results.append({{"name": name, "ea": hex(ea), "pseudocode": pseudo}})
print(json.dumps({{"has_hexrays": has_hexrays, "results": results, "count": len(results)}}))
""")
        if not result.get("has_hexrays"):
            return "ERROR: Hex-Rays decompiler not available in this IDA instance."
        funcs = result.get("results", [])
        parts = [
            _section(f"FUNCTION {f['name']} @ {f['ea']}", f.get("pseudocode") or "(no pseudocode)")
            for f in funcs
        ]
        count = result.get("count", len(funcs))
        return _section(
            f"DECOMPILED {count} FUNCTIONS (limit={limit})",
            "\n\n".join(parts) if parts else "(none)"
        )
    except Exception as e:
        return f"ERROR: {_friendly_error(str(e))}"


def _parse_addr(address: str) -> str:
    """Return an IDAPython-safe address expression from a string."""
    address = address.strip()
    if address.startswith("0x") or address.startswith("0X"):
        return str(int(address, 16))
    if re.fullmatch(r"[0-9a-fA-F]+", address) and len(address) >= 4:
        return str(int(address, 16))
    if re.fullmatch(r"\d+", address):
        return address
    # Symbol name — wrap in idc.get_name_ea_simple
    return f"idc.get_name_ea_simple({json.dumps(address)})"


# ---------------------------------------------------------------------------
# MCP JSON-RPC server (stdio transport — mirrors windbg_mcp.py pattern)
# ---------------------------------------------------------------------------

TOOLS: list[dict] = [
    {
        "name": "ida_status",
        "description": "Check if IDA Pro is connected and get binary info. Always call first.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_info",
        "description": "Get detailed binary info: path, arch, image base, entry point, size.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_functions",
        "description": "List functions in the binary. Supports pagination and name filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "description": "Pagination offset (default 0)"},
                "limit":  {"type": "integer", "description": "Max functions to return (default 100)"},
                "pattern": {"type": "string",  "description": "Filter by name substring (case-insensitive)"},
            },
            "required": [],
        },
    },
    {
        "name": "ida_segments",
        "description": "List all binary segments (.text, .data, .rdata, etc.) with addresses and permissions.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_imports",
        "description": "Get the import table, optionally filtered by DLL name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Optional DLL name filter (e.g. 'kernel32')"},
            },
            "required": [],
        },
    },
    {
        "name": "ida_exports",
        "description": "Get the export table (for DLLs/EXEs with exports).",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_strings",
        "description": "Find all strings in the binary. Useful for IOC extraction.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "min_len": {"type": "integer", "description": "Minimum string length (default 4)"},
                "limit":   {"type": "integer", "description": "Max strings to return (default 200)"},
            },
            "required": [],
        },
    },
    {
        "name": "ida_names",
        "description": "List all named addresses (functions, globals, labels) with optional pattern filter.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string",  "description": "Filter by name substring"},
                "limit":   {"type": "integer", "description": "Max names to return (default 200)"},
            },
            "required": [],
        },
    },
    {
        "name": "ida_disassemble",
        "description": "Disassemble instructions at an address. Use function=true for entire function.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address":  {"type": "string",  "description": "Address (hex '0x401000') or symbol name"},
                "count":    {"type": "integer", "description": "Number of instructions (default 20)"},
                "function": {"type": "boolean", "description": "If true, disassemble entire function"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_decompile",
        "description": "Decompile function to pseudocode using Hex-Rays decompiler.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address or name"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_analyze_function",
        "description": "Deep function analysis: calls, string refs, xrefs, decompile. Best starting point.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Function address or name"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_xrefs_to",
        "description": "Get all cross-references TO an address (who calls/references this).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string",  "description": "Target address or symbol"},
                "limit":   {"type": "integer", "description": "Max results (default 50)"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_xrefs_from",
        "description": "Get all cross-references FROM an address (what this calls/references).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string",  "description": "Source address or symbol"},
                "limit":   {"type": "integer", "description": "Max results (default 50)"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_rename",
        "description": "Rename a function, label, or global variable at an address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to rename"},
                "name":    {"type": "string", "description": "New name (IDA-valid identifier)"},
            },
            "required": ["address", "name"],
        },
    },
    {
        "name": "ida_comment",
        "description": "Add a comment at an address. Kinds: regular, repeatable, anterior, posterior.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to comment"},
                "text":    {"type": "string", "description": "Comment text"},
                "kind":    {
                    "type": "string",
                    "enum": ["regular", "repeatable", "anterior", "posterior"],
                    "description": "Comment type (default: regular)",
                },
            },
            "required": ["address", "text"],
        },
    },
    {
        "name": "ida_set_type",
        "description": "Set the type signature for a function or variable (C declaration syntax).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address":  {"type": "string", "description": "Address to type"},
                "type_str": {"type": "string", "description": "C type declaration, e.g. 'int __fastcall foo(HANDLE h, DWORD size)'"},
            },
            "required": ["address", "type_str"],
        },
    },
    {
        "name": "ida_get_type",
        "description": "Get the type signature of a function or variable.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to inspect"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_read_bytes",
        "description": "Read raw bytes at an address and show a hex+ASCII dump.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string",  "description": "Start address"},
                "size":    {"type": "integer", "description": "Number of bytes to read (default 64)"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_search",
        "description": "Search the binary for a byte pattern or string. kind: bytes|string|unicode",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string",  "description": "Byte pattern ('48 89 ?? 24') or string text"},
                "kind":    {"type": "string",  "description": "Search type: bytes, string, unicode (default: bytes)"},
                "limit":   {"type": "integer", "description": "Max hits (default 20)"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "ida_entry_points",
        "description": "List binary entry points (start address + DLL exports if applicable).",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_struct",
        "description": "Get struct definition from IDA's type library (name, members, offsets, sizes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Struct name (e.g. '_EPROCESS', 'HEAP')"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "ida_make_function",
        "description": "Force-create a function at an address (useful for undefined code regions).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Address to create function at"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_scan_bossix",
        "description": "Scan the binary for bossix imports, string indicators, and techniques.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_find_crypto",
        "description": "Scan for cryptographic algorithm indicators (constants, XOR patterns, S-boxes).",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_apply_signature",
        "description": "Apply a FLIRT .sig signature file to auto-identify library functions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sig_file": {"type": "string", "description": "Path to .sig file"},
            },
            "required": ["sig_file"],
        },
    },
    {
        "name": "ida_run_script",
        "description": "Execute raw IDAPython code inside IDA Pro. Escape hatch for any operation not covered by other tools.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "IDAPython code to execute. Use print() to get output. Import idc, idaapi, idautils as needed."},
            },
            "required": ["code"],
        },
    },
    {
        "name": "ida_diff_functions",
        "description": "Compare two functions side-by-side: disasm, instruction count, size delta. "
                       "Useful for spotting obfuscation differences or comparing similar routines.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "addr1": {"type": "string", "description": "Address or name of the first function"},
                "addr2": {"type": "string", "description": "Address or name of the second function"},
            },
            "required": ["addr1", "addr2"],
        },
    },
    {
        "name": "ida_call_tree",
        "description": "Build a recursive call tree from a function up to `depth` levels. "
                       "Returns a nested tree showing what functions are called. "
                       "Useful for understanding w execution flow or finding the main logic.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "Root function address or name"},
                "depth":   {"type": "integer", "description": "Recursion depth (default 3, max ~5 for large binaries)"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "ida_patch_bytes",
        "description": "Write bytes to the IDA database at an address using idc.patch_byte(). "
                       "Does NOT modify the original file — only the IDA database. "
                       "Useful for NOP-ing bossix checks found by ida_scan_bossix.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "address":   {"type": "string", "description": "Address to patch"},
                "hex_bytes": {"type": "string", "description": "Bytes to write: space-separated '90 90 90' or solid '909090'"},
            },
            "required": ["address", "hex_bytes"],
        },
    },
    {
        "name": "ida_list_patches",
        "description": "List all patches applied to the IDA database. "
                       "Shows address, original byte value, and patched byte value for each changed byte.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_export_idb_info",
        "description": "Export a comprehensive IDA database summary: input file path, MD5, SHA256, "
                       "image base, entry point count, function count, segment count, string count, "
                       "import module count, and patch count. Good for a session overview.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "ida_find_string_refs",
        "description": "Find all strings matching a regex pattern, then for each string list every "
                       "function that references it. Great for finding where 'admin', 'password', "
                       "'cmd.exe', or C2 URLs are used.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Python regex pattern (case-insensitive). Examples: 'admin', 'cmd\\.exe', 'password|passwd'"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "ida_get_pseudocode_all_functions",
        "description": "Decompile up to `limit` functions using Hex-Rays and return their pseudocode. "
                       "Starts from the first function in the binary. Useful for bulk analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max functions to decompile (default 20)"},
            },
            "required": [],
        },
    },
]


def _dispatch(name: str, args: dict) -> str:
    def g(k, default=None):
        v = args.get(k)
        return default if v is None else v

    if name == "ida_status":          return tool_status()
    if name == "ida_info":            return tool_info()
    if name == "ida_functions":       return tool_functions(g("offset", 0), g("limit", 100), g("pattern", ""))
    if name == "ida_segments":        return tool_segments()
    if name == "ida_imports":         return tool_imports(g("module", ""))
    if name == "ida_exports":         return tool_exports()
    if name == "ida_strings":         return tool_strings(g("min_len", 4), g("limit", 200))
    if name == "ida_names":           return tool_names(g("pattern", ""), g("limit", 200))
    if name == "ida_disassemble":     return tool_disassemble(g("address", "."), g("count", 20), bool(g("function", False)))
    if name == "ida_decompile":       return tool_decompile(g("address"))
    if name == "ida_analyze_function":return tool_analyze_function(g("address"))
    if name == "ida_xrefs_to":        return tool_xrefs_to(g("address"), g("limit", 50))
    if name == "ida_xrefs_from":      return tool_xrefs_from(g("address"), g("limit", 50))
    if name == "ida_rename":          return tool_rename(g("address"), g("name"))
    if name == "ida_comment":         return tool_comment(g("address"), g("text"), g("kind", "regular"))
    if name == "ida_set_type":        return tool_set_type(g("address"), g("type_str"))
    if name == "ida_get_type":        return tool_get_type(g("address"))
    if name == "ida_read_bytes":      return tool_read_bytes(g("address"), g("size", 64))
    if name == "ida_search":          return tool_search(g("pattern"), g("kind", "bytes"), g("limit", 20))
    if name == "ida_entry_points":    return tool_entry_points()
    if name == "ida_struct":          return tool_struct(g("name"))
    if name == "ida_make_function":   return tool_make_function(g("address"))
    if name == "ida_scan_bossix": return tool_scan_bossix()
    if name == "ida_find_crypto":     return tool_find_crypto()
    if name == "ida_apply_signature": return tool_apply_signature(g("sig_file"))
    if name == "ida_run_script":      return tool_run_script(g("code", ""))
    if name == "ida_diff_functions":  return tool_diff_functions(g("addr1"), g("addr2"))
    if name == "ida_call_tree":       return tool_call_tree(g("address"), g("depth", 3))
    if name == "ida_patch_bytes":     return tool_patch_bytes(g("address"), g("hex_bytes"))
    if name == "ida_list_patches":    return tool_list_patches()
    if name == "ida_export_idb_info": return tool_export_idb_info()
    if name == "ida_find_string_refs":return tool_find_string_refs(g("pattern", ""))
    if name == "ida_get_pseudocode_all_functions": return tool_get_pseudocode_all_functions(g("limit", 20))
    return f"Unknown tool: {name}"


def _respond(msg_id: Any, result: Any) -> None:
    out = json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})
    sys.stdout.write(out + "\n")
    sys.stdout.flush()


def _error(msg_id: Any, code: int, message: str) -> None:
    out = json.dumps({"jsonrpc": "2.0", "id": msg_id,
                      "error": {"code": code, "message": message}})
    sys.stdout.write(out + "\n")
    sys.stdout.flush()


def _serve() -> None:
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method  = msg.get("method", "")
        params  = msg.get("params") or {}

        if method == "initialize":
            _respond(msg_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            })
        elif method in ("initialized", "notifications/initialized"):
            pass
        elif method == "tools/list":
            _respond(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments") or {}
            try:
                result_text = _dispatch(tool_name, arguments)
            except Exception as exc:
                result_text = f"EXCEPTION: {exc}"
            _respond(msg_id, {
                "content": [{"type": "text", "text": result_text}]
            })
        elif method == "ping":
            _respond(msg_id, {})
        elif msg_id is not None:
            _error(msg_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    _serve()
