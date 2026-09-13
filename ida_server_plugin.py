"""
IDA Pro HTTP Server Plugin — run this inside IDA.

Starts an HTTP server on port 2022 (or IDA_SERVER_PORT) that accepts
IDAPython, executes it on IDA's main thread, and returns stdout.

Run in the IDA Python console:
    exec(open(r'C:\\path\\to\\ida_server_plugin.py').read())

Or copy to IDA plugins/:
    %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\ida_server_plugin.py

After start, ctxdebug's ida_mcp.py connects to http://127.0.0.1:2022
"""

from __future__ import annotations

import hmac
import http.server
import io
import ipaddress
import json
import os
import sys
import threading
import traceback

_IDA_SERVER_PORT = int(os.environ.get("IDA_SERVER_PORT", "2022"))
_IDA_SERVER_HOST = os.environ.get("IDA_SERVER_HOST", "127.0.0.1")
_IDA_SERVER_TOKEN = os.environ.get("IDA_MCP_TOKEN", "")
_server_instance = None
_server_thread = None
_ui_hooks = None

MAX_BODY_BYTES = 8 * 1024 * 1024


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _md5_hex(raw) -> str:
    """Normalize IDA's MD5 return (bytes, bytearray, or hex str) to hex."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).hex()
    text = str(raw).strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    return text


def _is_idaq() -> bool:
    try:
        import ida_kernwin
        return bool(ida_kernwin.is_idaq())
    except Exception:
        return False


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        if not _IDA_SERVER_TOKEN:
            return True
        provided = self.headers.get("Authorization") or ""
        return hmac.compare_digest(provided, f"Bearer {_IDA_SERVER_TOKEN}")

    def _host_is_loopback(self) -> bool:
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return _is_loopback(host)

    def _reject(self) -> bool:
        """Refuse browser-driven and untokenised non-loopback requests."""
        if self.headers.get("Origin") or self.headers.get("Referer"):
            self._send_json({"error": "Forbidden: cross-origin request"}, 403)
            return True
        if not _IDA_SERVER_TOKEN and not self._host_is_loopback():
            self._send_json({"error": "Forbidden: non-loopback Host without IDA_MCP_TOKEN"}, 403)
            return True
        if not self._check_auth():
            self._send_json({"error": "Unauthorized"}, 401)
            return True
        return False

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/health", "/api/v1/health"):
            # Liveness only — no IDA APIs, so it works before a DB is loaded.
            if self.headers.get("Origin") or self.headers.get("Referer"):
                self._send_json({"error": "Forbidden: cross-origin request"}, 403)
                return
            self._send_json({"ok": True, "server": "MCO ida_server_plugin"})
            return

        if self._reject():
            return

        if path in ("/", "/api/v1/info", "/info"):
            try:
                self._send_json(_on_ida_thread(_collect_info))
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self._reject():
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_json({"error": "invalid Content-Length"}, 400)
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json({"error": "payload too large"}, 413)
            return
        body_bytes = self.rfile.read(length) if length else b""
        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except json.JSONDecodeError:
            self._send_json({"error": "invalid JSON"}, 400)
            return

        code = body.get("code") or body.get("command") or body.get("input") or ""
        if not code:
            self._send_json({"error": 'missing "code" field'}, 400)
            return

        path = self.path.split("?", 1)[0]
        if path in ("/api/v1/py", "/api/v1/python", "/api/python", "/python",
                    "/exec", "/api/1/exec"):
            output, error = _exec_python(code)
            self._send_json({"output": output, "error": error or None})
        else:
            self._send_json({"error": f"unknown endpoint: {path}"}, 404)


def _bits_dll():
    """IDA 8.x / 9.x compatible (bits, is_dll)."""
    try:
        import ida_ida
        bits = 64 if ida_ida.inf_is_64bit() else 32
        is_dll = bool(ida_ida.inf_is_dll())
        return bits, is_dll
    except Exception:
        pass
    import idaapi
    try:
        info = idaapi.get_inf_structure()
        return (64 if info.is_64bit() else 32, bool(info.is_dll()))
    except Exception:
        bits = 64 if getattr(idaapi, "inf_is_64bit", lambda: False)() else 32
        is_dll = bool(getattr(idaapi, "inf_is_dll", lambda: False)())
        return bits, is_dll


def _collect_info() -> dict:
    """Snapshot of the loaded IDB. Safe when no database is open yet."""
    import idaapi
    import idc

    bits, is_dll = _bits_dll()
    md5 = ""
    try:
        if hasattr(idc, "retrieve_input_file_md5"):
            md5 = _md5_hex(idc.retrieve_input_file_md5())
    except Exception:
        md5 = ""

    proc = ""
    try:
        import ida_ida
        if hasattr(ida_ida, "inf_get_procname"):
            proc = ida_ida.inf_get_procname() or ""
    except Exception:
        proc = ""
    if not proc and hasattr(idaapi, "inf_get_procname"):
        try:
            proc = idaapi.inf_get_procname() or ""
        except Exception:
            proc = ""

    def _ea(getter, inf_attr):
        try:
            return hex(getter())
        except Exception:
            pass
        try:
            return hex(idc.get_inf_attr(inf_attr))
        except Exception:
            return "0x0"

    min_ea = "0x0"
    max_ea = "0x0"
    entry = "0x0"
    try:
        import ida_ida
        min_ea = _ea(ida_ida.inf_get_min_ea, getattr(idc, "INF_MIN_EA", 0))
        max_ea = _ea(ida_ida.inf_get_max_ea, getattr(idc, "INF_MAX_EA", 0))
        entry = _ea(ida_ida.inf_get_start_ip, getattr(idc, "INF_START_IP", 0))
    except Exception:
        try:
            min_ea = hex(idc.get_inf_attr(idc.INF_MIN_EA))
            max_ea = hex(idc.get_inf_attr(idc.INF_MAX_EA))
            entry = hex(idc.get_inf_attr(idc.INF_START_IP))
        except Exception:
            pass

    file_type = ""
    try:
        import ida_loader
        file_type = ida_loader.get_file_type_name() or ""
    except Exception:
        try:
            file_type = idc.get_file_type_name() if hasattr(idc, "get_file_type_name") else ""
        except Exception:
            file_type = ""

    try:
        input_file = idc.get_input_file_path() or ""
    except Exception:
        input_file = ""

    try:
        image_base = hex(idaapi.get_imagebase())
    except Exception:
        image_base = "0x0"

    return {
        "server": "MCO ida_server_plugin",
        "input_file": input_file,
        "processor": proc,
        "bits": bits,
        "image_base": image_base,
        "min_ea": min_ea,
        "max_ea": max_ea,
        "entry_point": entry,
        "file_type": file_type,
        "is_dll": is_dll,
        "input_md5": md5,
    }


def _on_ida_thread(fn, write: bool = False):
    """Run ``fn`` on IDA's main thread in GUI; inline in batch/idat.

    Never falls back to the HTTP thread after a main-thread failure — that
    path used to swallow the real error and crash IDA.
    """
    box = {"rv": None, "err": None}

    def _run():
        try:
            box["rv"] = fn()
        except Exception:
            box["err"] = traceback.format_exc()
        return 1

    synced = False
    if _is_idaq():
        try:
            import ida_kernwin
            flag = ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ
            ida_kernwin.execute_sync(_run, flag)
            synced = True
        except Exception:
            synced = False

    if not synced:
        _run()

    if box["err"]:
        raise RuntimeError(box["err"])
    return box["rv"]


def _exec_python(code: str):
    """Execute IDAPython on IDA's main thread, capture stdout, return (output, error)."""
    box = {"output": "", "error": None}

    def _run():
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        buf = io.StringIO()
        err_buf = io.StringIO()
        try:
            sys.stdout = buf
            sys.stderr = err_buf
            exec(compile(code, "<mco_script>", "exec"), _make_globals())
            box["output"] = buf.getvalue()
            box["error"] = err_buf.getvalue() or None
        except Exception:
            box["output"] = buf.getvalue()
            box["error"] = traceback.format_exc()
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
        return 1

    synced = False
    if _is_idaq():
        try:
            import ida_kernwin
            ida_kernwin.execute_sync(_run, ida_kernwin.MFF_WRITE)
            synced = True
        except Exception:
            synced = False
    if not synced:
        _run()
    return box["output"], box["error"]


def _make_globals() -> dict:
    """Build a namespace with common IDA modules pre-imported."""
    ns = {}
    for mod in (
        "idc", "idaapi", "idautils", "ida_bytes", "ida_funcs",
        "ida_hexrays", "ida_name", "ida_nalt", "ida_segment",
        "ida_typeinf", "ida_xref", "ida_ida", "ida_loader",
        "json", "struct", "re", "os", "sys",
    ):
        try:
            ns[mod] = __import__(mod)
        except ImportError:
            pass
    return ns


class _Server(http.server.HTTPServer):
    """Single-threaded HTTP server.

    GUI: serve_forever() runs on a daemon thread; handlers marshal onto IDA's
    main thread via execute_sync. Batch/idat: pump_forever() runs on the main
    thread so IDA 9's "main thread only" APIs succeed without a UI loop.
    ThreadingMixIn is intentionally not used — it would run handlers off-main
    in idat and crash with RuntimeError.
    """
    allow_reuse_address = True
    timeout = 0.25


def start(port: int | None = None, host: str | None = None):
    global _server_instance, _server_thread
    if _server_instance is not None:
        print(f"[MCO] Server already running on {_IDA_SERVER_HOST}:{_IDA_SERVER_PORT}")
        return

    bind_port = port or _IDA_SERVER_PORT
    bind_host = host or _IDA_SERVER_HOST

    if not _is_loopback(bind_host) and not _IDA_SERVER_TOKEN:
        raise RuntimeError(
            f"[MCO] Refusing to bind {bind_host}: set IDA_MCP_TOKEN before exposing "
            "the IDAPython exec endpoint off loopback, or bind 127.0.0.1."
        )
    if not _IDA_SERVER_TOKEN:
        print("[MCO] WARNING: IDA_MCP_TOKEN is not set — any local process can "
              "execute IDAPython through this port.")

    try:
        server = _Server((bind_host, bind_port), _Handler)
    except OSError as e:
        print(f"[MCO] Could not bind {bind_host}:{bind_port}: {e}")
        print("[MCO] If the plugin is already loaded, this is expected.")
        return

    _server_instance = server

    if _is_idaq():
        def _run():
            print(f"[MCO] IDA HTTP server started on http://{bind_host}:{bind_port}")
            server.serve_forever()

        t = threading.Thread(target=_run, daemon=True, name="mco-ida-server")
        t.start()
        _server_thread = t
        print("[MCO] ida_server_plugin loaded. Connect via ida_mcp.py")
    else:
        print(f"[MCO] IDA HTTP server listening on http://{bind_host}:{bind_port} (batch)")
        print("[MCO] Call ida_server_plugin.pump_forever() from the IDA main thread.")


def pump_forever():
    """Serve HTTP on the current thread until stop(). For idat / -S scripts."""
    global _server_instance
    if _server_instance is None:
        start()
    server = _server_instance
    if server is None:
        raise RuntimeError("[MCO] HTTP server failed to start")
    while _server_instance is server:
        try:
            server.handle_request()
        except Exception:
            traceback.print_exc()


def stop():
    global _server_instance, _server_thread
    if _server_instance:
        try:
            _server_instance.shutdown()
        except Exception:
            pass
        _server_instance = None
        _server_thread = None
        print("[MCO] IDA HTTP server stopped")
    else:
        print("[MCO] Server not running")


def _defer_start_until_ui_ready():
    """GUI: wait until IDA's UI (and usually the IDB) is ready."""
    global _ui_hooks
    try:
        import ida_kernwin
    except ImportError:
        start()
        return

    class _Hooks(ida_kernwin.UI_Hooks):
        def ready_to_run(self):
            start()
            self.unhook()
            return 0

    _ui_hooks = _Hooks()
    _ui_hooks.hook()


try:
    import idaapi

    class CtxdebugIdaPlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_KEEP
        comment = "ctxdebug IDA HTTP server (port 2022)"
        help = "HTTP IDAPython bridge for ctxdebug MCP"
        wanted_name = "ctxdebug IDA server"
        wanted_hotkey = ""

        def init(self):
            # Do not bind the port here: IDA loads plugins before the database
            # is open. GUI starts on ready_to_run; batch/idat starts via -S.
            if _is_idaq():
                _defer_start_until_ui_ready()
            return idaapi.PLUGIN_KEEP

        def run(self, arg):
            start()

        def term(self):
            stop()

    def PLUGIN_ENTRY():
        return CtxdebugIdaPlugin()
except ImportError:
    pass


# Only auto-start when this file is exec()'d as a script (File>Script / console).
# IDA 9 loads plugins under a name other than "ida_server_plugin", so a
# ``__name__ != "ida_server_plugin"`` check used to bind port 2022 during
# plugin import — before the database existed, and it blocked idat -S.
if __name__ == "__main__":
    existing = sys.modules.get("ida_server_plugin")
    if existing is not None and getattr(existing, "start", None):
        existing.start()
    else:
        start()
