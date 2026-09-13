"""Live IDA HTTP plugin test. Skips if idat.exe is not installed."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
IDAT = Path(r"C:\Program Files\IDA Professional 9.2\idat.exe")
NOTEPAD_SRC = Path(r"C:\Windows\System32\notepad.exe")


def _port_open(port: int = 2022) -> bool:
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _get(path: str, timeout: float = 15) -> dict:
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request("http://127.0.0.1:2022" + path)
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            last = e
            time.sleep(0.2)
    assert last is not None
    raise last


def _post_py(code: str, timeout: float = 20) -> dict:
    body = json.dumps({"code": code}).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:2022/api/v1/py",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


@pytest.fixture(scope="module")
def ida_http():
    if not IDAT.exists() or not NOTEPAD_SRC.exists():
        pytest.skip("IDA 9.2 / notepad.exe not available")
    subprocess.run(["taskkill", "/F", "/IM", "idat.exe"], capture_output=True)
    subprocess.run(["taskkill", "/F", "/IM", "ida.exe"], capture_output=True)
    time.sleep(0.5)
    if _port_open():
        pytest.skip("port 2022 already in use")

    tests = Path(__file__).resolve().parent
    sample = tests / "_sample_notepad.exe"
    log = tests / "_ida_http.log"
    ready = tests / "_ida_http_ready"
    script = tests / "_ida_http_keepalive.py"
    shutil.copy2(NOTEPAD_SRC, sample)
    for leftover in tests.glob("_sample_notepad.exe.*"):
        try:
            leftover.unlink()
        except OSError:
            pass
    if log.exists():
        log.unlink()
    if ready.exists():
        ready.unlink()

    plugin_src = ROOT / "ida_server_plugin.py"
    plugin_dst = (
        Path(os.environ.get("APPDATA", ""))
        / "Hex-Rays" / "IDA Pro" / "plugins" / "ida_server_plugin.py"
    )
    if plugin_src.exists() and plugin_dst.parent.exists():
        shutil.copy2(plugin_src, plugin_dst)

    proc = subprocess.Popen(
        [str(IDAT), "-A", "-c", "-L" + str(log), "-S" + str(script), str(sample)],
        cwd=str(tests),
    )
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            if ready.exists() and proc.poll() is None:
                try:
                    _get("/health", timeout=2)
                    break
                except Exception:
                    pass
            if proc.poll() is not None:
                tail = log.read_text(encoding="utf-8", errors="replace")[-1500:] if log.exists() else ""
                pytest.fail(f"idat exited {proc.returncode}: {tail}")
            time.sleep(1)
        else:
            tail = log.read_text(encoding="utf-8", errors="replace")[-1500:] if log.exists() else ""
            pytest.fail(f"idat HTTP did not come up: {tail}")
        yield proc
    finally:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
        subprocess.run(["taskkill", "/F", "/IM", "idat.exe"], capture_output=True)


def test_health(ida_http):
    info = _get("/health")
    assert info.get("ok") is True


def test_info_not_500(ida_http):
    info = _get("/api/v1/info")
    assert "error" not in info or not info["error"]
    assert info.get("server") == "MCO ida_server_plugin"
    assert info.get("bits") in (32, 64)
    assert info.get("input_file")


def test_exec_python_probe(ida_http):
    resp = _post_py("import json; print(json.dumps({'ok': True}))")
    assert resp.get("error") in (None, "")
    parsed = json.loads(resp["output"].strip().splitlines()[-1])
    assert parsed.get("ok") is True


def test_mcp_status_and_functions(ida_http):
    import ida_mcp
    ida_mcp._CLIENT = None
    os.environ["IDA_MCP_HOST"] = "127.0.0.1"
    os.environ["IDA_MCP_PORT"] = "2022"
    status = ida_mcp.tool_status()
    assert "NOT CONNECTED" not in status
    funcs = ida_mcp.tool_functions(0, 5)
    assert "FUNCTIONS" in funcs
