import inspect
import struct

from agent.bridge import MsgType, PIPE_MAGIC, PIPE_VERSION, PipeMessage
from mco_orchestrator import X64DbgOrchestratorClient


def test_pipe_message_uses_current_x64dbg_header_layout():
    msg = PipeMessage(
        msg_type=MsgType.COMMAND,
        seq_id=0x1234,
        payload={"cmd": "registers.get_all", "args": {}},
    )
    packed = msg.pack()

    magic, version, msg_type, payload_len, seq_id = struct.unpack("<4sHHII", packed[:16])

    assert magic == PIPE_MAGIC
    assert version == PIPE_VERSION
    assert msg_type == MsgType.COMMAND
    assert payload_len == len(packed) - PipeMessage.HEADER_SIZE
    assert seq_id == 0x1234


def test_orchestrator_does_not_own_x64dbg_wire_protocol():
    import mco_orchestrator

    source = inspect.getsource(mco_orchestrator)

    assert "class X64DbgClient" not in source
    assert 'struct.pack("<I"' not in source
    assert "resp_header[4:8]" not in source
    assert "X64DbgBridge" in source


def test_orchestrator_uses_plugin_command_namespace(monkeypatch):
    client = X64DbgOrchestratorClient()
    seen = []

    def fake_send(command, args=None, timeout=10.0):
        seen.append((command, args or {}))
        return {"ok": command}

    monkeypatch.setattr(client, "send_command", fake_send)

    assert client.get_registers() == {"ok": "registers.get_all"}
    assert client.get_peb() == {"ok": "process.peb"}
    assert client.get_modules() == {"ok": "modules.list"}
    assert client.get_threads() == {"ok": "threads.list"}
    assert [cmd for cmd, _ in seen] == [
        "registers.get_all",
        "process.peb",
        "modules.list",
        "threads.list",
    ]
