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

import http.server
import io
import json
import sys
import threading
import traceback

_IDA_SERVER_PORT = int(__import__('os').environ.get('IDA_SERVER_PORT', '2022'))
_IDA_SERVER_HOST = __import__('os').environ.get('IDA_SERVER_HOST', '127.0.0.1')
_IDA_SERVER_TOKEN = __import__('os').environ.get('IDA_MCP_TOKEN', '')
_server_instance = None
_server_thread   = None


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
        return self.headers.get('Authorization') == f"Bearer {_IDA_SERVER_TOKEN}"

    def do_GET(self):
        if not self._check_auth():
            self._send_json({'error': 'Unauthorized'}, 401)
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
        if not self._check_auth():
            self._send_json({'error': 'Unauthorized'}, 401)
            return

        length = int(self.headers.get('Content-Length', 0))
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
