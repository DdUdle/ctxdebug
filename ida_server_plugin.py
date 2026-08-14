"""
IDA Pro HTTP Server Plugin — запустить внутри IDA.

Этот скрипт запускает HTTP сервер на порту 2022 (или IDA_SERVER_PORT),
который принимает IDAPython код, выполняет его внутри IDA и возвращает stdout.

Запуск в IDA Python консоли:
    exec(open(r'C:\\path\\to\\ida_server_plugin.py').read())

Или добавить в IDA plugins/:
    cp ida_server_plugin.py "%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\"

После запуска MCO подключится автоматически к http://localhost:2022
"""

import hmac
import http.server
import io
import ipaddress
import json
import os
import sys
import threading
import traceback

_IDA_SERVER_PORT = int(os.environ.get('IDA_SERVER_PORT', '2022'))
_IDA_SERVER_HOST = os.environ.get('IDA_SERVER_HOST', '127.0.0.1')
_IDA_SERVER_TOKEN = os.environ.get('IDA_MCP_TOKEN', '')
_server_instance = None
_server_thread   = None

MAX_BODY_BYTES = 8 * 1024 * 1024


def _is_loopback(host: str) -> bool:
    if host in ('localhost', ''):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # silence access log

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        if not _IDA_SERVER_TOKEN:
            return True
        provided = self.headers.get('Authorization') or ''
        return hmac.compare_digest(provided, f"Bearer {_IDA_SERVER_TOKEN}")

    def _host_is_loopback(self) -> bool:
        host = (self.headers.get('Host') or '').rsplit(':', 1)[0].strip('[]')
        return _is_loopback(host)

    def _reject(self) -> bool:
        """Send an error response unless the request may execute IDAPython.

        Browser-driven requests are always refused (CSRF / DNS rebinding against
        this port), and an untokenised server only answers loopback Hosts.
        """
        if self.headers.get('Origin') or self.headers.get('Referer'):
            self._send_json({'error': 'Forbidden: cross-origin request'}, 403)
            return True
        if not _IDA_SERVER_TOKEN and not self._host_is_loopback():
            self._send_json({'error': 'Forbidden: non-loopback Host without IDA_MCP_TOKEN'}, 403)
            return True
        if not self._check_auth():
            self._send_json({'error': 'Unauthorized'}, 401)
            return True
        return False

    def do_GET(self):
        if self._reject():
            return

        if self.path in ('/', '/api/v1/info', '/info'):
            try:
                import idc, idaapi
                info = idaapi.get_inf_structure()
                self._send_json({
                    'server': 'MCO ida_server_plugin',
                    'input_file': idc.get_input_file_path(),
                    'processor': idaapi.inf_get_procname() if hasattr(idaapi, 'inf_get_procname') else '',
                    'bits': 64 if info.is_64bit() else 32,
                    'image_base': hex(idaapi.get_imagebase()),
                    'min_ea': hex(idc.get_inf_attr(idc.INF_MIN_EA)),
                    'max_ea': hex(idc.get_inf_attr(idc.INF_MAX_EA)),
                    'entry_point': hex(idc.get_inf_attr(idc.INF_START_IP)),
                    'file_type': idc.get_file_type_name(),
                    'is_dll': bool(info.is_dll()),
                    'input_md5': idc.retrieve_input_file_md5().hex() if hasattr(idc, 'retrieve_input_file_md5') else '',
                })
            except Exception as e:
                self._send_json({'error': str(e)}, 500)
        else:
            self._send_json({'error': 'not found'}, 404)

    def do_POST(self):
        if self._reject():
            return

        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            self._send_json({'error': 'invalid Content-Length'}, 400)
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json({'error': 'payload too large'}, 413)
            return
        body_bytes = self.rfile.read(length) if length else b''
        try:
            body = json.loads(body_bytes.decode('utf-8')) if body_bytes else {}
        except json.JSONDecodeError:
            self._send_json({'error': 'invalid JSON'}, 400)
            return

        # Accept code from any of these keys
        code = body.get('code') or body.get('command') or body.get('input') or ''

        if not code:
            self._send_json({'error': 'missing "code" field'}, 400)
            return

        if self.path in ('/api/v1/py', '/api/v1/python', '/api/python', '/python',
                          '/exec', '/api/1/exec'):
            output, error = _exec_python(code)
            self._send_json({'output': output, 'error': error or None})
        else:
            self._send_json({'error': f'unknown endpoint: {self.path}'}, 404)


def _exec_python(code: str):
    """Execute IDAPython code, capture stdout, return (output, error)."""
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    buf = io.StringIO()
    err_buf = io.StringIO()
    try:
        sys.stdout = buf
        sys.stderr = err_buf
        exec(compile(code, '<mco_script>', 'exec'), _make_globals())
        output = buf.getvalue()
        error  = err_buf.getvalue() or None
        return output, error
    except Exception:
        error = traceback.format_exc()
        output = buf.getvalue()
        return output, error
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr


def _make_globals() -> dict:
    """Build a namespace with common IDA modules pre-imported."""
    ns = {}
    for mod in ('idc', 'idaapi', 'idautils', 'ida_bytes', 'ida_funcs',
                 'ida_hexrays', 'ida_name', 'ida_nalt', 'ida_segment',
                 'ida_struct', 'ida_typeinf', 'ida_xref', 'json', 'struct',
                 're', 'os', 'sys'):
        try:
            ns[mod] = __import__(mod)
        except ImportError:
            pass
    return ns


def start(port: int | None = None, host: str | None = None):
    global _server_instance, _server_thread
    if _server_instance is not None:
        print(f'[MCO] Server already running on {_IDA_SERVER_HOST}:{_IDA_SERVER_PORT}')
        return

    bind_port = port or _IDA_SERVER_PORT
    bind_host = host or _IDA_SERVER_HOST

    # The server executes arbitrary IDAPython, so binding off loopback requires
    # a token.
    if not _is_loopback(bind_host) and not _IDA_SERVER_TOKEN:
        raise RuntimeError(
            f'[MCO] Refusing to bind {bind_host}: set IDA_MCP_TOKEN before exposing '
            'the IDAPython exec endpoint off loopback, or bind 127.0.0.1.'
        )
    if not _IDA_SERVER_TOKEN:
        print('[MCO] WARNING: IDA_MCP_TOKEN is not set — any local process can '
              'execute IDAPython through this port.')

    server = http.server.HTTPServer((bind_host, bind_port), _Handler)
    _server_instance = server

    def _run():
        print(f'[MCO] IDA HTTP server started on http://{bind_host}:{bind_port}')
        server.serve_forever()

    t = threading.Thread(target=_run, daemon=True, name='mco-ida-server')
    t.start()
    _server_thread = t
    print(f'[MCO] ida_server_plugin loaded. Claude can now connect via ida_mcp.py')


def stop():
    global _server_instance, _server_thread
    if _server_instance:
        _server_instance.shutdown()
        _server_instance = None
        _server_thread   = None
        print('[MCO] IDA HTTP server stopped')
    else:
        print('[MCO] Server not running')


# Auto-start when run as a script (exec() or File > Script file)
if __name__ != 'ida_server_plugin':
    start()
