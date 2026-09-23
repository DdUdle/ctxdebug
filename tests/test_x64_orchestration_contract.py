import inspect
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import mco_orchestrator
from agent.bridge import X64DbgBridge
from agent.x64_protocol import (
    MsgType,
    PIPE_HEADER_SIZE,
    PIPE_HEADER_STRUCT,
    PIPE_MAGIC,
    PIPE_VERSION,
    PipeMessage,
)


def test_response_header_uses_versioned_layout_not_legacy_length_field():
    message = PipeMessage(
        msg_type=MsgType.RESPONSE,
        seq_id=7,
        payload={"ok": True, "value": 123},
    ).pack()

    magic, version, msg_type, payload_len, seq_id = PIPE_HEADER_STRUCT.unpack(
        message[:PIPE_HEADER_SIZE]
    )

    assert magic == PIPE_MAGIC
    assert version == PIPE_VERSION == 1
    assert msg_type == MsgType.RESPONSE == 2
    assert seq_id == 7
    assert payload_len == len(message) - PIPE_HEADER_SIZE

    # This is the exact legacy-orchestrator bug: bytes 4:8 are
    # version + msg_type, which decode to 131073 as a uint32.
    assert int.from_bytes(message[4:8], "little") == 131073
    assert int.from_bytes(message[4:8], "little") != payload_len

    unpacked = PipeMessage.unpack(message)
    assert unpacked.payload == {"ok": True, "value": 123}


@pytest.mark.asyncio
async def test_bridge_high_level_methods_use_plugin_command_namespace():
    bridge = X64DbgBridge()
    seen = []

    async def fake_send(command, args=None, timeout=10.0):
        seen.append(command)
        if command == "modules.list":
            return {"modules": []}
        if command == "threads.list":
            return {"threads": []}
        if command == "registers.get_all":
            return {"rip": 0x401000}
        if command == "process.peb":
            return {"address": "0x1000"}
        return {}

    bridge.send_command = fake_send

    assert await bridge.get_registers() == {"rip": 0x401000}
    assert await bridge.get_peb() == {"address": "0x1000"}
    assert await bridge.get_modules() == []
    assert await bridge.get_threads() == []

    assert seen == [
        "registers.get_all",
        "process.peb",
        "modules.list",
        "threads.list",
    ]


def test_native_pipe_header_mirrors_python_wire_contract():
    cpp = (
        Path(__file__).resolve().parents[1]
        / "agent"
        / "plugins"
        / "x64dbg_plugin.cpp"
    ).read_text(encoding="utf-8", errors="replace")

    start = cpp.index("struct PipeHeader {")
    end = cpp.index("#pragma pack(pop)", start)
    header = cpp[start:end]
    fields = [
        "char     magic[4]",
        "uint16_t version",
        "uint16_t msg_type",
        "uint32_t payload_len",
        "uint32_t seq_id",
    ]
    positions = [header.index(field) for field in fields]

    assert positions == sorted(positions)
    assert 'static_assert(sizeof(PipeHeader) == 16' in cpp
    assert "constexpr uint16_t PIPE_VERSION = 1;" in cpp
    assert PIPE_HEADER_SIZE == 16
    assert PIPE_VERSION == 1


def test_plugin_registers_all_orchestrator_p0_handlers():
    cpp = (
        Path(__file__).resolve().parents[1]
        / "agent"
        / "plugins"
        / "x64dbg_plugin.cpp"
    ).read_text(encoding="utf-8", errors="replace")

    for command in (
        "registers.get_all",
        "process.peb",
        "modules.list",
        "threads.list",
    ):
        assert f'g_handlers["{command}"]' in cpp

    assert "hdr.version != PIPE_VERSION" in cpp

    # modules.list / threads.list return arrays of objects. The previous
    # single-`first` JsonBuilder emitted invalid JSON like `[{}{}]`.
    assert "std::vector<Context> stack;" in cpp
    assert "ctx.kind == ContainerKind::ARRAY" in cpp
    assert "if (!ctx.first) s += ',';" in cpp


def test_plugin_json_builder_emits_valid_object_arrays(tmp_path):
    compiler = shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        pytest.skip("standalone JsonBuilder contract requires g++ or clang++")

    cpp = (
        Path(__file__).resolve().parents[1]
        / "agent"
        / "plugins"
        / "x64dbg_plugin.cpp"
    ).read_text(encoding="utf-8", errors="replace")
    start = cpp.index("class JsonBuilder {")
    end = cpp.index("\nstatic std::string hex64", start)
    builder = cpp[start:end]

    source = tmp_path / "json_builder_contract.cpp"
    exe = tmp_path / ("json_builder_contract.exe" if os.name == "nt" else "json_builder_contract")
    source.write_text(
        """
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
"""
        + builder
        + r"""
int main() {
    JsonBuilder j;
    j.begin_object().key("modules").begin_array();
    j.begin_object().key("name").val("a").key("size").val((uint64_t)1).end_object();
    j.begin_object().key("name").val("b").key("size").val((uint64_t)2).end_object();
    j.end_array().key("ok").val(true).end_object();
    std::printf("%s", j.str().c_str());
}
""",
        encoding="utf-8",
    )

    subprocess.run(
        [compiler, "-std=c++20", str(source), "-o", str(exe)],
        check=True,
        capture_output=True,
        text=True,
    )
    completed = subprocess.run(
        [str(exe)],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == {
        "modules": [
            {"name": "a", "size": 1},
            {"name": "b", "size": 2},
        ],
        "ok": True,
    }


def test_orchestrator_uses_shared_bridge_not_private_pipe_client():
    source = inspect.getsource(mco_orchestrator)
    assert "class X64DbgClient" not in source

    orchestrator = mco_orchestrator.MCOOrchestrator()
    try:
        assert isinstance(orchestrator.x64, X64DbgBridge)
    finally:
        orchestrator.close()


def test_windbg_runtime_address_normalizes_to_rva():
    lm_output = """
start             end                 module name
00007ff6`12000000 00007ff6`12200000   sample
"""
    runtime = 0x00007FF612123456
    base = mco_orchestrator._extract_module_base(lm_output, runtime)

    assert base == 0x00007FF612000000
    assert mco_orchestrator._runtime_to_rva(runtime, base) == 0x123456


def test_fault_ip_parser_handles_symbol_line_before_address():
    analyze = """
FAULT_IP:
sample!crash_here+0x16
00007ff6`12123456 488b01          mov     rax,qword ptr [rcx]
"""
    assert mco_orchestrator._extract_crash_address(analyze) == 0x00007FF612123456


def test_faulting_ip_parser_handles_standard_windbg_spelling():
    analyze = """
FAULTING_IP:
sample!crash_here+0x16
00007ff6`12123456 488b01          mov     rax,qword ptr [rcx]
"""
    assert mco_orchestrator._extract_crash_address(analyze) == 0x00007FF612123456


def test_crash_to_source_passes_rva_to_ida(tmp_path):
    dump = tmp_path / "sample.dmp"
    dump.write_bytes(b"dump")

    runtime = 0x00007FF612123456
    base = 0x00007FF612000000
    expected_rva = 0x123456

    class FakeCdb:
        DEFAULT_CDB = "cdb.exe"
        connected = True

        def open_dump(self, dump_path):
            return "loaded"

        def run(self, command, timeout=30):
            if command == "!analyze -v":
                return (
                    "ExceptionAddress: "
                    "00007ff6`12123456 (sample!crash_here+0x16)"
                )
            if command.startswith("lm a "):
                return (
                    "start             end                 module name\n"
                    "00007ff6`12000000 00007ff6`12200000 sample"
                )
            raise AssertionError(command)

        def close(self):
            pass

    class FakeIda:
        available = True

        def exec_python(self, code):
            assert f"runtime_address = {runtime}" in code
            assert f"runtime_module_base = {base}" in code
            assert f"rva = {expected_rva}" in code
            assert "addr = ida_imagebase + rva" in code
            return json.dumps(
                {
                    "runtime_address": hex(runtime),
                    "runtime_module_base": hex(base),
                    "rva": hex(expected_rva),
                    "ida_imagebase": "0x140000000",
                    "ida_address": hex(0x140000000 + expected_rva),
                    "function": "crash_here",
                }
            )

    orchestrator = mco_orchestrator.MCOOrchestrator()
    orchestrator.cdb = FakeCdb()
    orchestrator.ida = FakeIda()
    try:
        result = orchestrator.crash_to_source(str(dump))
    finally:
        orchestrator.close()

    assert result["address_normalization"] == {
        "runtime_address": hex(runtime),
        "runtime_module_base": hex(base),
        "rva": hex(expected_rva),
    }
    assert result["ida_analysis"]["ida_address"] == hex(0x140000000 + expected_rva)


def test_x64_module_lookup_supports_hex_bases():
    module = mco_orchestrator._find_runtime_module(
        [
            {"base": "0x180000000", "size": 0x2000, "name": "other.dll"},
            {"base": "0x7ff612000000", "size": 0x200000, "name": "sample.exe"},
        ],
        0x7FF612123456,
    )
    assert module is not None
    assert module["name"] == "sample.exe"
    assert module["_base_int"] == 0x7FF612000000


def test_pivot_to_ida_uses_explicit_runtime_base_for_aslr():
    runtime = 0x7FF612123456
    base = 0x7FF612000000
    expected_rva = 0x123456

    class FakeIda:
        available = True

        def exec_python(self, code):
            assert f"input_addr = {runtime}" in code
            assert f"rva = {expected_rva}" in code
            assert "addr = ida_imagebase + rva if rva is not None else input_addr" in code
            return json.dumps(
                {
                    "input_address": hex(runtime),
                    "rva": hex(expected_rva),
                    "ida_imagebase": "0x140000000",
                    "ida_address": hex(0x140000000 + expected_rva),
                    "function_name": "crash_here",
                }
            )

    orchestrator = mco_orchestrator.MCOOrchestrator()
    orchestrator.ida = FakeIda()
    try:
        result = orchestrator.pivot_to_ida(
            hex(runtime),
            runtime_module_base=hex(base),
        )
    finally:
        orchestrator.close()

    assert result["address_normalization"] == {
        "runtime_address": hex(runtime),
        "runtime_module_base": hex(base),
        "rva": hex(expected_rva),
        "runtime_module": None,
        "source": "explicit_runtime_module_base",
    }
    assert result["ida_address"] == hex(0x140000000 + expected_rva)


def test_orchestrator_p0_workflows_call_shared_bridge_high_level_api():
    calls = []

    class FakeIda:
        available = False

    class FakeBridge:
        pipe_name = r"\\.\pipe\test_x64dbg"

        def __init__(self):
            self.connected = True

        async def connect(self):
            calls.append("connect")
            self.connected = True
            return True

        async def disconnect(self):
            calls.append("disconnect")
            self.connected = False

        async def get_peb(self):
            calls.append("get_peb")
            return {"address": "0x1000", "being_debugged": 0}

        async def get_registers(self):
            calls.append("get_registers")
            return {"rip": 0x401000}

        async def get_modules(self):
            calls.append("get_modules")
            return [{"base": "0x400000", "size": 0x10000, "name": "sample.exe"}]

        async def get_threads(self):
            calls.append("get_threads")
            return [{"tid": 1234}]

    orchestrator = mco_orchestrator.MCOOrchestrator()
    orchestrator.x64 = FakeBridge()
    orchestrator.ida = FakeIda()
    try:
        bossix = orchestrator.bossix_report()
        audit = orchestrator.quick_w_audit()
    finally:
        orchestrator.close()

    assert bossix["x64dbg_dynamic"]["peb"]["address"] == "0x1000"
    assert bossix["x64dbg_dynamic"]["registers"]["rip"] == 0x401000
    assert audit["x64dbg_runtime"]["modules"][0]["name"] == "sample.exe"
    assert audit["x64dbg_runtime"]["threads"][0]["tid"] == 1234
    assert calls == [
        "get_peb",
        "get_registers",
        "get_modules",
        "get_threads",
        "disconnect",
    ]
