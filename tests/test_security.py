import ast

import ida_mcp
import ida_server_plugin


def test_plugin_import_does_not_bind_port():
    assert ida_server_plugin._server_instance is None


def test_md5_hex():
    assert ida_server_plugin._md5_hex(None) == ""
    assert ida_server_plugin._md5_hex(b"\xde\xad") == "dead"
    assert ida_server_plugin._md5_hex("DEAD") == "DEAD"
    assert ida_server_plugin._md5_hex("0xdead") == "dead"


def test_on_ida_thread_runs_inline_without_ida():
    assert ida_server_plugin._on_ida_thread(lambda: 7) == 7


def test_loopback_detection():
    assert ida_server_plugin._is_loopback("127.0.0.1")
    assert ida_server_plugin._is_loopback("localhost")
    assert ida_server_plugin._is_loopback("::1")
    assert not ida_server_plugin._is_loopback("0.0.0.0")
    assert not ida_server_plugin._is_loopback("10.0.0.5")
    assert not ida_server_plugin._is_loopback("evil.example.com")


def test_int_bounds():
    assert ida_mcp._int("50", 10, 1, 100) == 50
    assert ida_mcp._int(500, 10, 1, 100) == 100
    assert ida_mcp._int(-5, 10, 1, 100) == 1
    assert ida_mcp._int("; import os", 10, 1, 100) == 10
    assert ida_mcp._int(None, 10, 1, 100) == 10


def test_parse_addr_rejects_injection():
    assert ida_mcp._parse_addr("0x401000") == str(0x401000)
    assert ida_mcp._parse_addr(401000) == str(0x401000)
    name = 'main"); import os; os.system("id'
    quoted = ida_mcp._parse_addr(name)
    call = ast.parse(quoted, mode="eval").body
    assert isinstance(call, ast.Call)
    assert [ast.literal_eval(a) for a in call.args] == [name]
