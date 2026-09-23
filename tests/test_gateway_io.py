import json
import subprocess
import sys
import time

import pytest

import mco_gateway


def _spawn_child(script_path):
    return subprocess.Popen(
        [sys.executable, str(script_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def test_rpc_timeout_is_real_when_child_never_replies(tmp_path):
    child = tmp_path / "silent_child.py"
    child.write_text(
        "import sys, time\n"
        "for _line in sys.stdin:\n"
        "    time.sleep(60)\n",
        encoding="utf-8",
    )

    server = mco_gateway.SubServer(
        {"name": "silent", "cmd": [sys.executable, str(child)]}
    )
    server.proc = _spawn_child(child)
    server._start_readers()

    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            server._rpc("never-replies", {}, timeout=0.2)
    finally:
        server.stop()

    assert time.monotonic() - started < 2.0


def test_stderr_is_drained_while_waiting_for_rpc_response(tmp_path):
    child = tmp_path / "noisy_child.py"
    child.write_text(
        "import json, sys\n"
        "line = sys.stdin.readline()\n"
        "req = json.loads(line)\n"
        "for i in range(12000):\n"
        "    sys.stderr.write(('noise-%05d-' % i) + ('x' * 180) + '\\n')\n"
        "sys.stderr.flush()\n"
        "print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':{'ok':True}}), flush=True)\n"
        "for _line in sys.stdin:\n"
        "    pass\n",
        encoding="utf-8",
    )

    server = mco_gateway.SubServer(
        {"name": "noisy", "cmd": [sys.executable, str(child)]}
    )
    server.proc = _spawn_child(child)
    server._start_readers()
    try:
        response = server._rpc("ping", {}, timeout=5.0)
    finally:
        server.stop()

    assert response["result"] == {"ok": True}
    assert server._stderr_tail
    assert len(server._stderr_tail) <= 50


def test_rebuild_tool_map_drops_stale_routes():
    class FakeServer:
        def __init__(self, running, tools):
            self.running = running
            self.tools = tools

    old = FakeServer(False, [{"name": "old_tool"}])
    live = FakeServer(True, [{"name": "new_tool"}])

    gateway = object.__new__(mco_gateway.Gateway)
    gateway.servers = [old, live]
    gateway.tool_map = {"old_tool": old}

    gateway._rebuild_tool_map()

    assert "old_tool" not in gateway.tool_map
    assert gateway.tool_map == {"new_tool": live}


def test_rpc_no_longer_calls_blocking_stdout_readline():
    import inspect

    source = inspect.getsource(mco_gateway.SubServer._rpc)
    assert "stdout.readline" not in source
    assert "_stdout_q.get" in source
    assert "time.monotonic()" in source
