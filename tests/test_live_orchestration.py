"""Optional live acceptance tests for the cross-debugger workflows.

These tests are intentionally skipped in normal CI because they require real
Windows debugger processes. Run them manually on the analysis workstation.

Environment:
    MCO_LIVE_X64DBG=1
        x64dbg is open with the MCO plugin loaded and a target attached.

    MCO_LIVE_CRASH_DUMP=C:\\path\\to\\crash.dmp
        cdb.exe is installed, IDA HTTP is live with the matching binary loaded,
        and the dump belongs to that binary.
"""

from __future__ import annotations

import os
import sys

import pytest

from mco_orchestrator import MCOOrchestrator


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="live debugger acceptance tests require Windows",
)


def test_live_x64dbg_orchestrator_acceptance():
    if os.environ.get("MCO_LIVE_X64DBG") != "1":
        pytest.skip("set MCO_LIVE_X64DBG=1 to run against a live x64dbg")

    orchestrator = MCOOrchestrator()
    try:
        status = orchestrator.debugger_status()
        assert status["x64dbg"]["available"] is True

        bossix = orchestrator.bossix_report()
        dynamic = bossix["x64dbg_dynamic"]
        assert "error" not in dynamic
        assert isinstance(dynamic.get("peb"), dict)
        assert dynamic.get("registers") is not None

        audit = orchestrator.quick_w_audit()
        runtime = audit["x64dbg_runtime"]
        assert "error" not in runtime
        assert isinstance(runtime.get("modules"), list)
        assert isinstance(runtime.get("threads"), list)
    finally:
        orchestrator.close()


def test_live_x64dbg_rip_pivots_to_ida_through_rva():
    if os.environ.get("MCO_LIVE_X64DBG") != "1":
        pytest.skip("set MCO_LIVE_X64DBG=1 to run against a live x64dbg")

    orchestrator = MCOOrchestrator()
    try:
        status = orchestrator.debugger_status()
        if not status["ida"]["available"]:
            pytest.skip("IDA HTTP server is not available")

        dynamic = orchestrator._x64_bossix_snapshot()
        registers = dynamic.get("registers") or {}
        rip = registers.get("rip")
        assert isinstance(rip, int) and rip > 0

        pivot = orchestrator.pivot_to_ida(hex(rip))
        assert "error" not in pivot
        normalization = pivot["address_normalization"]
        assert normalization["source"] == "x64dbg_modules"
        assert normalization["runtime_module_base"] is not None
        assert normalization["rva"] is not None
        assert pivot.get("ida_address") is not None
    finally:
        orchestrator.close()


def test_live_windbg_dump_pivots_to_ida_through_rva():
    dump_path = os.environ.get("MCO_LIVE_CRASH_DUMP")
    if not dump_path:
        pytest.skip("set MCO_LIVE_CRASH_DUMP to run WinDbg -> IDA acceptance")

    orchestrator = MCOOrchestrator()
    try:
        status = orchestrator.debugger_status()
        assert status["windbg"]["available"] is True
        assert status["ida"]["available"] is True

        result = orchestrator.crash_to_source(dump_path)
        assert "error" not in result
        normalization = result["address_normalization"]
        assert normalization["runtime_module_base"] is not None
        assert normalization["rva"] is not None
        assert result.get("ida_analysis", {}).get("ida_address") is not None
    finally:
        orchestrator.close()
