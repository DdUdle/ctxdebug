import hmac
import string

import ida_server_plugin


def test_missing_ida_token_generates_256_bit_secret():
    token, generated = ida_server_plugin._resolve_server_token("")
    assert generated is True
    assert len(token) == 64
    assert all(ch in string.hexdigits for ch in token)


def test_explicit_ida_token_is_preserved():
    token, generated = ida_server_plugin._resolve_server_token("configured-secret")
    assert token == "configured-secret"
    assert generated is False


def test_ida_exec_auth_is_fail_closed(monkeypatch):
    monkeypatch.setattr(ida_server_plugin, "_IDA_SERVER_TOKEN", "secret")

    handler = object.__new__(ida_server_plugin._Handler)
    handler.headers = {}
    assert handler._check_auth() is False

    handler.headers = {"Authorization": "Bearer wrong"}
    assert handler._check_auth() is False

    handler.headers = {"Authorization": "Bearer secret"}
    assert handler._check_auth() is True


def test_auth_uses_constant_time_compare():
    assert ida_server_plugin.hmac.compare_digest is hmac.compare_digest
