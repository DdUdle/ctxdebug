import json

import ida_mcp


def test_endpoint_probe_rejects_generic_json():
    assert not ida_mcp._endpoint_probe_succeeded({"error": "not found"}, "output")
    assert not ida_mcp._endpoint_probe_succeeded({"hello": "world"}, "output")
    assert not ida_mcp._endpoint_probe_succeeded({"output": "nope"}, "output")


def test_endpoint_probe_accepts_ok_payload():
    body = json.dumps({"ok": True})
    assert ida_mcp._endpoint_probe_succeeded({"output": body, "error": None}, "output")
    assert ida_mcp._endpoint_probe_succeeded({"output": "log line\n" + body}, "output")


def test_json_from_ida_output_ignores_prefix():
    payload = {"alive": True, "n": 2}
    raw = "warning: something\n" + json.dumps(payload)
    assert ida_mcp._json_from_ida_output(raw) == payload


def test_json_from_ida_output_trailing_text():
    assert ida_mcp._json_from_ida_output('{"ok": true} leftover') == {"ok": True}


def test_plugin_source_is_real():
    from pathlib import Path
    cpp = Path(__file__).resolve().parents[1] / "agent" / "plugins" / "x64dbg_plugin.cpp"
    text = cpp.read_text(encoding="utf-8", errors="replace")
    assert cpp.stat().st_size > 1000
    assert "X64A" in text
    assert "<FULL FILE CONTENT>" not in text
    assert "FindMem" in text
