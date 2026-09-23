import inspect
import os
from pathlib import Path

import pytest

from agent.bridge import BridgeProtocol, ConnectionState, X64DbgBridge
import mco_gateway


def test_gateway_generates_shared_x64dbg_capability():
    env = {}
    token = mco_gateway._ensure_x64dbg_pipe_token(env)
    assert len(token) == 64
    assert env["X64DBG_PIPE_TOKEN"] == token
    assert mco_gateway._ensure_x64dbg_pipe_token(env) == token


@pytest.mark.asyncio
async def test_named_pipe_connect_requires_auth_token(monkeypatch):
    monkeypatch.delenv("X64DBG_PIPE_TOKEN", raising=False)
    bridge = X64DbgBridge(auth_token="")
    called = False

    async def fake_connect_pipe():
        nonlocal called
        called = True
        return True

    bridge._connect_pipe = fake_connect_pipe
    assert await bridge.connect() is False
    assert called is False
    assert bridge.state == ConnectionState.DISCONNECTED


@pytest.mark.asyncio
async def test_named_pipe_mode_does_not_downgrade_to_http():
    bridge = X64DbgBridge(auth_token="a" * 64)
    calls = []

    async def pipe():
        calls.append("pipe")
        return False

    async def http():
        calls.append("http")
        return True

    bridge._connect_pipe = pipe
    bridge._connect_http = http
    assert await bridge.connect() is False
    assert calls == ["pipe"]


@pytest.mark.asyncio
async def test_explicit_http_mode_still_uses_http():
    bridge = X64DbgBridge(protocol=BridgeProtocol.HTTP)

    async def http():
        return True

    bridge._connect_http = http
    assert await bridge.connect() is True
    assert bridge.protocol == BridgeProtocol.HTTP


def test_bridge_uses_mutual_hmac_without_sending_raw_token():
    source = inspect.getsource(X64DbgBridge)
    assert "hmac.new(" in source
    assert '"auth_challenge"' in source
    assert '"proof": self._auth_proof("client"' in source
    assert "expected_server_proof" in source
    assert 'payload={"cmd": command, "args": args}' in source
    assert 'child_env["X64DBG_PIPE_TOKEN"] = self.auth_token' in source


def test_native_pipe_security_contract_is_fail_closed():
    cpp = (
        Path(__file__).resolve().parents[1]
        / "agent"
        / "plugins"
        / "x64dbg_plugin.cpp"
    ).read_text(encoding="utf-8", errors="replace")

    assert "ConvertStringSecurityDescriptorToSecurityDescriptorW" in cpp
    assert "OpenProcessToken" in cpp
    assert "GetNamedPipeClientProcessId" in cpp
    assert 'json_get_string(auth_payload, "proof")' in cpp
    assert 'json_get_string(auth_payload, "nonce")' in cpp
    assert 'SetEnvironmentVariableA("X64DBG_PIPE_TOKEN", nullptr)' in cpp
    assert "BCryptGenRandom" in cpp
    assert "BCryptCreateHash" in cpp
    assert "BCRYPT_ALG_HANDLE_HMAC_FLAG" in cpp
    assert "FILE_FLAG_FIRST_PIPE_INSTANCE" in cpp
    assert "client_pid == target_pid" in cpp
    assert "PIPE_WORKER_COUNT = 4" in cpp
    assert "g_pipe_threads" in cpp
    assert "g_command_mutex" in cpp
