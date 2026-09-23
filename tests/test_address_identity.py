import mco_orchestrator
from mco_identity import AddressIdentity, compare_identity_to_ida, parse_windbg_lmv_build


def test_windbg_lmv_extracts_build_identity():
    parsed = parse_windbg_lmv_build(
        """
start             end                 module name
00007ff6`12000000 00007ff6`12200000 sample
    Image path: C:\\build\\sample.exe
    Image name: sample.exe
    Timestamp:        65A1B2C3
    ImageSize:        00200000
"""
    )
    assert parsed["pe_timestamp"] == 0x65A1B2C3
    assert parsed["pe_size_of_image"] == 0x200000
    assert parsed["build_id"] == "pe:65a1b2c3:200000"


def test_build_identity_rejects_same_name_different_binary():
    identity = AddressIdentity(
        address=0x7FF612123456,
        source="x64dbg_modules",
        module="sample.exe",
        runtime_base=0x7FF612000000,
        rva=0x123456,
        pe_timestamp=0x11111111,
        pe_size_of_image=0x200000,
    )
    verification = compare_identity_to_ida(
        identity,
        {
            "input_file": r"C:\\other\\sample.exe",
            "pe_timestamp": 0x22222222,
            "pe_size_of_image": 0x200000,
        },
    )
    assert verification["compatible"] is False
    assert "pe_timestamp" in verification["mismatches"]
    assert verification["build_verified"] is False


def test_build_identity_accepts_matching_timestamp_and_size():
    identity = AddressIdentity(
        address=0x7FF612123456,
        source="x64dbg_modules",
        module="sample.exe",
        runtime_base=0x7FF612000000,
        rva=0x123456,
        pe_timestamp=0x65A1B2C3,
        pe_size_of_image=0x200000,
    )
    verification = compare_identity_to_ida(
        identity,
        {
            "input_file": r"C:\\symbols\\sample.exe",
            "pe_timestamp": 0x65A1B2C3,
            "pe_size_of_image": 0x200000,
        },
    )
    assert verification["compatible"] is True
    assert verification["build_verified"] is True
    assert verification["runtime_build_id"] == verification["ida_build_id"]


def test_pivot_refuses_mismatched_x64dbg_build_before_decompile():
    class FakeIda:
        def ping(self):
            return True

        def get_info(self):
            return {
                "input_file": r"C:\\ida\\sample.exe",
                "pe_timestamp": 0x22222222,
                "pe_size_of_image": 0x200000,
            }

        def exec_python(self, code):
            raise AssertionError("decompile must not run after identity mismatch")

    class FakeBridge:
        pipe_name = r"\\.\pipe\test"
        connected = True

        async def connect(self):
            return True

        async def disconnect(self):
            self.connected = False

        async def get_modules(self):
            return [{
                "base": "0x7ff612000000",
                "size": 0x200000,
                "size_of_image": 0x200000,
                "timestamp": 0x11111111,
                "name": "sample.exe",
            }]

    orchestrator = mco_orchestrator.MCOOrchestrator()
    orchestrator.ida = FakeIda()
    orchestrator.x64 = FakeBridge()
    try:
        result = orchestrator.pivot_to_ida("0x7ff612123456")
    finally:
        orchestrator.close()

    assert result["error"] == "ida_image_identity_mismatch"
    assert result["address_identity"]["rva"] == "0x123456"
    assert "pe_timestamp" in result["ida_identity_verification"]["mismatches"]


def test_explicit_runtime_base_requires_build_identity_by_default():
    class FakeIda:
        def ping(self):
            return True

        def get_info(self):
            return {
                "input_file": r"C:\\ida\\sample.exe",
                "pe_timestamp": 0x65A1B2C3,
                "pe_size_of_image": 0x200000,
            }

    orchestrator = mco_orchestrator.MCOOrchestrator()
    orchestrator.ida = FakeIda()
    try:
        result = orchestrator.pivot_to_ida(
            "0x7ff612123456",
            runtime_module_base="0x7ff612000000",
        )
    finally:
        orchestrator.close()

    assert result["error"] == "runtime_image_identity_unverified"


def test_size_only_is_not_enough_to_verify_build():
    identity = AddressIdentity(
        address=0x7FF612123456,
        source="legacy_modules",
        module="sample.exe",
        runtime_base=0x7FF612000000,
        rva=0x123456,
        pe_size_of_image=0x200000,
    )
    verification = compare_identity_to_ida(
        identity,
        {
            "input_file": r"C:\\ida\\sample.exe",
            "pe_size_of_image": 0x200000,
        },
    )
    assert verification["compatible"] is True
    assert verification["build_verified"] is False


def test_windbg_lmv_parses_standard_dated_timestamp():
    parsed = parse_windbg_lmv_build(
        """
    Timestamp:        Fri Jun  2 06:06:07 2023 (6479950F)
    ImageSize:        00046000
"""
    )
    assert parsed["pe_timestamp"] == 0x6479950F
    assert parsed["pe_size_of_image"] == 0x46000
    assert parsed["build_id"] == "pe:6479950f:46000"


def test_module_identity_normalizes_windows_paths_cross_platform():
    identity = AddressIdentity(
        address=0x140001000,
        source="test",
        module=r"C:\\build\\sample.exe",
        runtime_base=0x140000000,
        rva=0x1000,
        pe_timestamp=0x65A1B2C3,
        pe_size_of_image=0x200000,
    )
    verification = compare_identity_to_ida(
        identity,
        {
            "input_file": r"D:\\symbols\\sample.exe",
            "pe_timestamp": 0x65A1B2C3,
            "pe_size_of_image": 0x200000,
        },
    )
    assert verification["compatible"] is True
    assert verification["checks"]["module"]["match"] is True
