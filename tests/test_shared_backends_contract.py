import inspect
import json

import ida_mcp
import mco_orchestrator
import windbg_mcp
from windbg_backend import CdbSession


def test_orchestrator_imports_shared_backend_clients():
    source = inspect.getsource(mco_orchestrator)

    assert "class CdbClient" not in source
    assert "class IDAClient" not in source
    assert "from ida_mcp import IDAClient" in source
    assert "from windbg_backend import CdbSession" in source

    orchestrator = mco_orchestrator.MCOOrchestrator()
    try:
        assert isinstance(orchestrator.cdb, CdbSession)
        assert isinstance(orchestrator.ida, ida_mcp.IDAClient)
    finally:
        orchestrator.close()


def test_windbg_mcp_uses_shared_cdb_session():
    assert windbg_mcp.CdbSession is CdbSession
    source = inspect.getsource(windbg_mcp)
    assert "class CdbSession" not in source
    assert "from windbg_backend import" in source


def test_shared_backend_environment_names(monkeypatch, tmp_path):
    fake_cdb = tmp_path / "cdb.exe"
    fake_cdb.write_bytes(b"")
    monkeypatch.setenv("WINDBG_MCP_CDB", str(fake_cdb))
    monkeypatch.setenv("IDA_MCP_HOST", "127.0.0.9")
    monkeypatch.setenv("IDA_MCP_PORT", "31337")

    cdb = CdbSession()
    ida = ida_mcp.IDAClient()

    assert cdb.cdb_path == str(fake_cdb)
    assert cdb.available is True
    assert ida.host == "127.0.0.9"
    assert ida.port == 31337


def test_example_config_uses_shared_backend_environment_names():
    with open("mcp_config_example.json", "r", encoding="utf-8") as f:
        config = json.load(f)

    env = config["mcpServers"]["mco"]["env"]
    assert "WINDBG_MCP_CDB" in env
    assert "IDA_MCP_HOST" in env
    assert "IDA_MCP_PORT" in env
    assert "CDB_PATH" not in env
    assert "IDA_HOST" not in env
    assert "IDA_PORT" not in env
