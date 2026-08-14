"""Tests for the shared parsing and formatting utilities."""

import io
import json
import sys

from agent.skills import parse_address, parse_int
from mco_common import kv_block, section, serve_stdio, text_error, text_result


def test_parse_address():
    assert parse_address(None) == 0
    assert parse_address(None, 5) == 5
    assert parse_address(0x140001000) == 0x140001000
    assert parse_address("0x140001000") == 0x140001000
    assert parse_address("0X1F") == 0x1F
    # Long all-hex strings without a prefix are treated as hex.
    assert parse_address("deadbeef") == 0xDEADBEEF
    # Short unprefixed values stay decimal.
    assert parse_address("123") == 123
    assert parse_address("  0x20  ") == 0x20
    assert parse_address("", 9) == 9
    assert parse_address("not-an-address", 9) == 9


def test_parse_int():
    assert parse_int(None) == 0
    assert parse_int(None, 10) == 10
    assert parse_int(42) == 42
    assert parse_int("42") == 42
    assert parse_int("0x2a") == 42
    assert parse_int("0X2A") == 42
    # Unlike parse_address, unprefixed hex-looking values stay decimal.
    assert parse_int("100000") == 100000
    assert parse_int("  7  ") == 7
    assert parse_int("", 3) == 3
    assert parse_int("garbage", 3) == 3


def test_section():
    assert section("Title", "body") == "### Title\nbody"
    assert section("Title", "\nbody\n") == "### Title\nbody"
    assert section("Title", "") == "### Title\n(empty)"
    assert section("Title", None) == "### Title\n(empty)"


def test_kv_block():
    assert kv_block([]) == "(none)"
    assert kv_block([("a", 1)]) == "a = 1"
    # Keys are padded to a common width.
    assert kv_block([("rax", 1), ("r", 2)]) == "rax = 1\nr   = 2"


def test_text_result():
    assert text_result("hello") == {
        "content": [{"type": "text", "text": "hello"}],
        "isError": False,
    }
    result = text_result({"a": 1})
    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"]) == {"a": 1}


def test_text_error():
    assert text_error("boom") == {
        "content": [{"type": "text", "text": "ERROR: boom"}],
        "isError": True,
    }


def test_serve_stdio(monkeypatch, capsys):
    seen = []

    def handle(request):
        seen.append(request)
        if request.get("method") == "quiet":
            return None
        return {"echo": request["method"]}

    lines = "\n".join([
        "",  # blank lines are skipped
        "not json",  # undecodable lines are skipped
        json.dumps({"method": "quiet"}),
        json.dumps({"method": "ping"}),
    ])
    monkeypatch.setattr(sys, "stdin", io.StringIO(lines))

    serve_stdio(handle)

    assert seen == [{"method": "quiet"}, {"method": "ping"}]
    # Only the non-None handler response is written out.
    assert capsys.readouterr().out == json.dumps({"echo": "ping"}) + "\n"
