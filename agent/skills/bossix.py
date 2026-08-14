"""
Bossix Skills — detect and bypass bossix techniques.

This is one of the KEY differentiators from plain MCP servers.
Instead of just calling "hide debugger", the agent:
1. Scans for known bossix patterns
2. Identifies which techniques are used
3. Suggests targeted patches
4. Can auto-patch common checks
"""

from . import SkillDefinition, SkillResult, SkillRegistry, parse_address


# Common bossix techniques and their signatures
BOSSIX_CHECKS = {
    "IsDebuggerPresent": {
        "description": "Basic API check — checks PEB.BeingDebugged",
        "api": "IsDebuggerPresent",
        "bypass": "Set breakpoint, change return value to 0",
        "pattern_x64": "65 48 8B 04 25 60 00 00 00 0F B6 40 02",
    },
    "NtQueryInformationProcess_DebugPort": {
        "description": "Checks DebugPort (class 7) via NtQueryInformationProcess",
        "api": "NtQueryInformationProcess",
        "bypass": "Hook API or zero the output buffer",
    },
    "NtQueryInformationProcess_DebugFlags": {
        "description": "Checks ProcessDebugFlags (class 0x1F)",
        "api": "NtQueryInformationProcess",
        "bypass": "Hook API, set output to 1",
    },
    "NtQueryInformationProcess_DebugObjectHandle": {
        "description": "Checks ProcessDebugObjectHandle (class 0x1E)",
        "api": "NtQueryInformationProcess",
        "bypass": "Hook API, return STATUS_PORT_NOT_SET",
    },
    "CheckRemoteDebuggerPresent": {
        "description": "Calls NtQueryInformationProcess internally",
        "api": "CheckRemoteDebuggerPresent",
        "bypass": "Set breakpoint, change output bool to FALSE",
    },
    "PEB_BeingDebugged": {
        "description": "Direct PEB access via TEB (gs:[0x60])",
        "pattern_x64": "65 48 8B 04 25 60 00 00 00 0F B6 40 02",
        "bypass": "Patch PEB.BeingDebugged to 0",
    },
    "PEB_NtGlobalFlag": {
        "description": "NtGlobalFlag check (0x70 when debugged due to heap flags)",
        "pattern_x64": "65 48 8B 04 25 60 00 00 00 8B 40 BC",
        "bypass": "Clear NtGlobalFlag (set to 0)",
    },
    "RDTSC_Timing": {
        "description": "RDTSC-based timing check — measures execution time",
        "pattern_x64": "0F 31",
        "bypass": "NOP the comparison or hook RDTSC via VEH",
    },
    "INT3_Scan": {
        "description": "Scans for INT3 (0xCC) software breakpoints in code",
        "bypass": "Use hardware breakpoints instead",
    },
    "NtSetInformationThread_HideFromDebugger": {
        "description": "Hides thread from debugger (class 0x11)",
        "api": "NtSetInformationThread",
        "bypass": "Hook API, NOP the call",
    },
    "CloseHandle_Exception": {
        "description": "Calls CloseHandle with invalid handle, checks for exception",
        "api": "CloseHandle",
        "bypass": "Don't pass exception to debugger",
    },
    "OutputDebugString": {
        "description": "Calls OutputDebugStringA, checks GetLastError",
        "api": "OutputDebugStringA",
        "bypass": "Set breakpoint, fix return value",
    },
    "VEH_Trap": {
        "description": "Uses VEH/SEH to detect single-stepping or breakpoints",
        "bypass": "Don't pass hardware exceptions to debugger",
    },
}


async def skill_scan_bossix(bridge, context, args):
    """Scan for bossix techniques in the binary."""
    found_techniques = []
    scan_results = []

    # 1. Check PEB flags
    peb = await bridge.get_peb()
    if peb and "error" not in peb:
        if peb.get("being_debugged"):
            found_techniques.append("PEB_BeingDebugged (flag is SET)")
        nt_flag = peb.get("nt_global_flag", 0)
        if nt_flag & 0x70:
            found_techniques.append(f"PEB_NtGlobalFlag (0x{nt_flag:X}, debug heap flags present)")

    # 2. Search for API imports
    imports = await bridge.get_imports()
    import_names = set()
    for imp in imports:
        name = imp.get("name", "")
        import_names.add(name)

    api_checks = [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugStringA", "OutputDebugStringW",
    ]
    for api in api_checks:
        if api in import_names:
            found_techniques.append(f"Import: {api}")
            scan_results.append(BOSSIX_CHECKS.get(api, {}))

    # 3. Search for known patterns
    for name, info in BOSSIX_CHECKS.items():
        pattern = info.get("pattern_x64")
        if pattern:
            results = await bridge.search_pattern(pattern)
            if results:
                found_techniques.append(f"Pattern: {name} at {len(results)} location(s)")
                for r in results[:3]:
                    addr = r.get("address", 0)
                    scan_results.append({
                        "technique": name,
                        "address": addr,
                        "bypass": info.get("bypass", ""),
                    })

    # 4. Search for RDTSC instructions
    rdtsc_results = await bridge.search_pattern("0F 31")
    if rdtsc_results:
        found_techniques.append(f"RDTSC instructions: {len(rdtsc_results)} found")

    # Build report
    lines = [f"Bossix Scan Results:"]
    if found_techniques:
        lines.append(f"\nDetected {len(found_techniques)} potential bossix techniques:")
        for i, tech in enumerate(found_techniques, 1):
            lines.append(f"  {i}. {tech}")

        lines.append("\nRecommended bypasses:")
        seen = set()
        for result in scan_results:
            if isinstance(result, dict):
                tech = result.get("technique", "")
                bypass = result.get("bypass", "")
                addr = result.get("address", 0)
                key = f"{tech}_{addr}"
                if key not in seen and bypass:
                    seen.add(key)
                    if addr:
                        lines.append(f"  - 0x{addr:X} [{tech}]: {bypass}")
                    else:
                        lines.append(f"  - [{tech}]: {bypass}")
    else:
        lines.append("\nNo common bossix techniques detected.")

    context.patterns_found.extend(
        {"pattern": t, "results": ""} for t in found_techniques
    )

    return SkillResult(
        success=True,
        data={"techniques": found_techniques, "details": scan_results},
        summary=f"Bossix scan: {len(found_techniques)} techniques found",
        details="\n".join(lines),
        suggestions=["hide_bossix", "patch_bossix", "set_breakpoint"] if found_techniques else [],
    )


async def skill_hide_bossix(bridge, context, args):
    """Hide debugger from common detection methods."""
    hidden = []
    failed = []

    # 1. Use x64dbg's built-in hide
    result = await bridge.hide_bossix()
    if result:
        hidden.append("x64dbg built-in hide (PEB patch)")

    # 2. Patch PEB.BeingDebugged
    peb = await bridge.get_peb()
    if peb and "error" not in peb:
        peb_addr = peb.get("address", 0)
        if peb_addr:
            # PEB.BeingDebugged is at offset +2 (x64)
            success = await bridge.write_memory(peb_addr + 2, b'\x00')
            if success:
                hidden.append("PEB.BeingDebugged = 0")
            else:
                failed.append("PEB.BeingDebugged patch")

            # NtGlobalFlag at offset +0xBC (x64)
            from struct import pack
            success = await bridge.write_memory(peb_addr + 0xBC, pack('<I', 0))
            if success:
                hidden.append("PEB.NtGlobalFlag = 0")
            else:
                failed.append("NtGlobalFlag patch")

    lines = ["Debugger hiding results:"]
    for h in hidden:
        lines.append(f"  [OK] {h}")
    for f in failed:
        lines.append(f"  [FAIL] {f}")

    return SkillResult(
        success=len(hidden) > 0,
        data={"hidden": hidden, "failed": failed},
        summary=f"Hidden debugger: {len(hidden)} patches applied, {len(failed)} failed",
        details="\n".join(lines),
        suggestions=["scan_bossix"],
    )


async def skill_patch_bossix(bridge, context, args):
    """Auto-patch a specific bossix check."""
    address = args.get("address")
    technique = args.get("technique", "")

    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    address = parse_address(address)

    # Get instruction at address to determine patch
    disasm = await bridge.disassemble(address, 5)
    if not disasm:
        return SkillResult(success=False, summary=f"Cannot disassemble at 0x{address:X}")

    first_instr = disasm[0]
    mnemonic = first_instr.get("mnemonic", "").lower()
    instr_size = first_instr.get("size", 0)

    patched = False
    patch_desc = ""

    # Common patches
    if mnemonic == "call":
        # Patch CALL to return 0: xor eax,eax; NOP remaining
        patch = b'\x31\xC0'  # xor eax, eax
        patch += b'\x90' * (instr_size - 2)  # NOP padding
        patched = await bridge.write_memory(address, patch)
        patch_desc = f"Patched CALL at 0x{address:X} to XOR EAX,EAX + NOP"

    elif mnemonic in ("je", "jne", "jz", "jnz"):
        # Flip conditional jump
        instr_bytes_hex = first_instr.get("bytes", "")
        if instr_bytes_hex:
            instr_bytes = bytes.fromhex(instr_bytes_hex.replace(" ", ""))
            if len(instr_bytes) == 2:
                # Short jump: flip bit 0 of opcode
                new_opcode = instr_bytes[0] ^ 1
                patched = await bridge.write_memory(address, bytes([new_opcode, instr_bytes[1]]))
                patch_desc = f"Flipped conditional jump at 0x{address:X}"
            elif len(instr_bytes) == 6 and instr_bytes[0] == 0x0F:
                new_opcode = instr_bytes[1] ^ 1
                patched = await bridge.write_memory(address + 1, bytes([new_opcode]))
                patch_desc = f"Flipped near conditional jump at 0x{address:X}"

    elif mnemonic == "test" or mnemonic == "cmp":
        # NOP the test/cmp instruction
        patch = b'\x90' * instr_size
        patched = await bridge.write_memory(address, patch)
        patch_desc = f"NOPed {mnemonic.upper()} at 0x{address:X}"

    else:
        # Generic: NOP the instruction
        patch = b'\x90' * instr_size
        patched = await bridge.write_memory(address, patch)
        patch_desc = f"NOPed instruction at 0x{address:X}"

    return SkillResult(
        success=patched,
        summary=patch_desc if patched else f"Failed to patch at 0x{address:X}",
        suggestions=["scan_bossix", "run"],
    )


def register_bossix_skills(registry: SkillRegistry):
    skills = [
        SkillDefinition(
            name="scan_bossix",
            description="Scan binary for bossix techniques (PEB, API imports, patterns, RDTSC)",
            category="bossix", execute=skill_scan_bossix,
        ),
        SkillDefinition(
            name="hide_bossix",
            description="Hide debugger from detection (PEB patch, NtGlobalFlag, built-in hide)",
            category="bossix", execute=skill_hide_bossix,
        ),
        SkillDefinition(
            name="patch_bossix",
            description="Auto-patch bossix check at address (flip jumps, NOP calls)",
            args_schema={"address": "int/hex", "technique": "technique name"},
            category="bossix", execute=skill_patch_bossix,
        ),
    ]
    for s in skills:
        registry.register(s)
