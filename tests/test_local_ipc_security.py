import inspect
from pathlib import Path

import agent.bridge
import ida_server_plugin


def test_ida_exec_endpoint_has_secure_token_default():
    source = inspect.getsource(ida_server_plugin)
    assert "secrets.token_urlsafe(32)" in source
    assert "if not _IDA_SERVER_TOKEN:\n            return True" not in source
    assert 'hmac.compare_digest(provided, f"Bearer {_IDA_SERVER_TOKEN}")' in source
    assert ida_server_plugin._IDA_SERVER_TOKEN
    assert len(ida_server_plugin._IDA_SERVER_TOKEN) >= 32


def test_x64_named_pipe_is_local_acl_and_pid_bound():
    cpp = (
        Path(__file__).resolve().parents[1]
        / "agent"
        / "plugins"
        / "x64dbg_plugin.cpp"
    ).read_text(encoding="utf-8", errors="replace")

    assert "PIPE_REJECT_REMOTE_CLIENTS" in cpp
    assert "ConvertSidToStringSidW" in cpp
    assert "ConvertStringSecurityDescriptorToSecurityDescriptorW" in cpp
    assert "GetNamedPipeClientProcessId" in cpp
    assert 'CTXDEBUG_CONTROLLER_PID' in cpp
    assert "client_pid != g_trusted_controller_pid" in cpp
    assert "CTXDEBUG_ALLOW_UNTRUSTED_PIPE" in cpp
    assert "65536, 65536, 0, &sa" in cpp


def test_bridge_launch_binds_plugin_to_controller_pid():
    source = inspect.getsource(agent.bridge.X64DbgBridge.launch_x64dbg)
    assert 'child_env["CTXDEBUG_CONTROLLER_PID"] = str(os.getpid())' in source
    assert "env=child_env" in source
