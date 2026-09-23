import inspect
import json

import ida_mcp
import mco_orchestrator
import windbg_mcp


def test_orchestrator_uses_shared_backend_clients():
    source = inspect.getsource(mco_orchestrator)
    assert "class IDAClient" not in source
    assert "class CdbClient" not in source
    assert "urllib.request.Request" not in source
    assert "subprocess.Popen" not in source

    orchestrator = mco_orchestrator.MCOOrchestrator()
    try:
        assert isinstance(orchestrator.ida, ida_mcp.IDAClient)
        assert isinstance(orchestrator.cdb, windbg_mcp.CdbSession)
        assert orchestrator.ida.host == ida_mcp.IDAClient().host
        assert orchestrator.cdb.cdb_path == windbg_mcp.CdbSession().cdb_path
    finally:
        orchestrator.close()


def test_orchestrator_ida_client_uses_json_execution_contract(monkeypatch):
    client = ida_mcp.IDAClient(host="127.0.0.1", port=2022)
    requests = []

    def fake_post(path, body):
        requests.append((path, body))
        parsed = json.loads(body)
        assert isinstance(parsed, dict)
        code = parsed.get("code") or parsed.get("command") or parsed.get("input")
        assert code
        return {"output": json.dumps({"ok": True}), "error": None}

    monkeypatch.setattr(client, "_post", fake_post)
    path, _, _ = client._discover_py_endpoint()

    assert path == "/api/v1/py"
    assert requests
    assert json.loads(requests[0][1])["code"]


def test_orchestrator_no_longer_owns_legacy_backend_env_names():
    source = inspect.getsource(mco_orchestrator)
    assert "IDA_HOST" not in source
    assert "IDA_PORT" not in source
    assert "CDB_PATH" not in source
    assert "IDA_MCP_HOST" in source
    assert "IDA_MCP_PORT" in source
    assert "WINDBG_MCP_CDB" in source
