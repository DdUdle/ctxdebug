"""
Breakpoint Skills — software, hardware, memory, conditional breakpoints.
"""

from . import SkillDefinition, SkillResult, SkillRegistry


async def skill_set_breakpoint(bridge, context, args):
    """Set software breakpoint."""
    address = args.get("address")
    api = args.get("api")  # Can set BP by API name

    if api:
        # Resolve API to address via x64dbg expression evaluation
        resolved = await bridge.evaluate_expression(api)
        if resolved is None:
            return SkillResult(success=False, summary=f"Cannot resolve API: {api}")
        address = resolved

    if address is None:
        return SkillResult(success=False, summary="Missing 'address' or 'api' argument")

    if isinstance(address, str):
        address = int(address, 16) if address.startswith("0x") else int(address)

    result = await bridge.set_breakpoint(address)
    success = "error" not in result

    if success:
        context.breakpoints.append({"address": address, "type": "software", "api": api})

    return SkillResult(
        success=success,
        data=result,
        summary=f"{'Set' if success else 'Failed to set'} breakpoint at 0x{address:X}" +
                (f" ({api})" if api else ""),
        suggestions=["run", "get_registers"],
    )


async def skill_set_hardware_breakpoint(bridge, context, args):
    """Set hardware breakpoint (execute, read, write)."""
    address = args.get("address")
    condition = args.get("condition", "execute")  # "execute", "read", "write", "readwrite"
    size = args.get("size", 1)  # 1, 2, 4, 8

    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    if isinstance(address, str):
        address = int(address, 16) if address.startswith("0x") else int(address)

    result = await bridge.set_hardware_breakpoint(address, size, condition)
    success = "error" not in result

    if success:
        context.breakpoints.append({
            "address": address, "type": "hardware",
            "condition": condition, "size": size,
        })

    return SkillResult(
        success=success,
        data=result,
        summary=f"{'Set' if success else 'Failed to set'} HW BP ({condition}, {size}B) at 0x{address:X}",
        suggestions=["run", "get_registers"],
    )


async def skill_set_memory_breakpoint(bridge, context, args):
    """Set memory breakpoint (access/write on range)."""
    address = args.get("address")
    size = args.get("size", 1)
    access_type = args.get("access_type", "write")  # "read", "write", "access"

    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    if isinstance(address, str):
        address = int(address, 16) if address.startswith("0x") else int(address)

    # Use x64dbg command for memory breakpoints
    cmd = f"bpm {address:X}, 0, {'w' if access_type == 'write' else 'r' if access_type == 'read' else 'rw'}"
    result = await bridge.execute_command(cmd)
    success = "error" not in result

    return SkillResult(
        success=success,
        data=result,
        summary=f"{'Set' if success else 'Failed to set'} memory BP ({access_type}) at 0x{address:X}",
    )


async def skill_delete_breakpoint(bridge, context, args):
    """Delete breakpoint at address."""
    address = args.get("address")
    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    if isinstance(address, str):
        address = int(address, 16) if address.startswith("0x") else int(address)

    result = await bridge.delete_breakpoint(address)
    success = "error" not in result

    if success:
        context.breakpoints = [bp for bp in context.breakpoints if bp.get("address") != address]

    return SkillResult(
        success=success,
        summary=f"{'Deleted' if success else 'Failed to delete'} breakpoint at 0x{address:X}",
    )


async def skill_set_conditional_breakpoint(bridge, context, args):
    """Set breakpoint with condition (e.g., break when rcx == 0x1000)."""
    address = args.get("address")
    condition = args.get("condition", "")  # x64dbg condition expression
    log_text = args.get("log", "")

    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    if isinstance(address, str):
        address = int(address, 16) if address.startswith("0x") else int(address)

    # First set the breakpoint
    await bridge.set_breakpoint(address)

    # Then set condition
    if condition:
        await bridge.execute_command(f"bpcnd {address:X}, \"{condition}\"")

    # Set log if specified
    if log_text:
        await bridge.execute_command(f"bplog {address:X}, \"{log_text}\"")

    context.breakpoints.append({
        "address": address, "type": "conditional",
        "condition": condition, "log": log_text,
    })

    summary = f"Set conditional BP at 0x{address:X}"
    if condition:
        summary += f" when [{condition}]"
    if log_text:
        summary += f" logging [{log_text}]"

    return SkillResult(success=True, summary=summary, suggestions=["run"])


async def skill_bp_on_api(bridge, context, args):
    """Set breakpoints on common API groups."""
    group = args.get("group", "")
    api_groups = {
        "memory": [
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "VirtualFree", "HeapAlloc", "HeapFree",
        ],
        "process": [
            "CreateProcessA", "CreateProcessW", "CreateRemoteThread",
            "CreateRemoteThreadEx", "OpenProcess", "TerminateProcess",
        ],
        "file": [
            "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
            "DeleteFileA", "DeleteFileW",
        ],
        "registry": [
            "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
            "RegQueryValueExA", "RegQueryValueExW",
        ],
        "network": [
            "connect", "send", "recv", "WSAStartup",
            "InternetOpenA", "InternetOpenW",
            "HttpOpenRequestA", "HttpOpenRequestW",
        ],
        "inject": [
            "WriteProcessMemory", "NtWriteVirtualMemory",
            "CreateRemoteThread", "NtCreateThreadEx",
            "QueueUserAPC", "NtQueueApcThread",
        ],
        "crypto": [
            "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
            "CryptHashData", "CryptDeriveKey",
        ],
        "bossix": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "OutputDebugStringA",
        ],
    }

    if group not in api_groups:
        return SkillResult(
            success=False,
            summary=f"Unknown API group: {group}. Available: {', '.join(api_groups.keys())}",
        )

    apis = api_groups[group]
    set_count = 0
    failed = []

    for api in apis:
        resolved = await bridge.evaluate_expression(api)
        if resolved:
            result = await bridge.set_breakpoint(resolved)
            if "error" not in result:
                set_count += 1
                context.breakpoints.append({"address": resolved, "type": "software", "api": api})
            else:
                failed.append(api)
        else:
            failed.append(api)

    summary = f"Set {set_count}/{len(apis)} breakpoints for [{group}] API group"
    details = ""
    if failed:
        details = f"Failed to resolve: {', '.join(failed)}"

    return SkillResult(
        success=set_count > 0,
        data={"set": set_count, "total": len(apis), "failed": failed},
        summary=summary,
        details=details,
        suggestions=["run"],
    )


def register_breakpoint_skills(registry: SkillRegistry):
    skills = [
        SkillDefinition(
            name="set_breakpoint", description="Set software breakpoint (by address or API name)",
            args_schema={"address": "int/hex", "api": "API name (alternative to address)"},
            category="breakpoints", execute=skill_set_breakpoint,
        ),
        SkillDefinition(
            name="set_hw_breakpoint", description="Set hardware breakpoint (execute/read/write)",
            args_schema={"address": "int/hex", "condition": "execute/read/write/readwrite", "size": "1/2/4/8"},
            category="breakpoints", execute=skill_set_hardware_breakpoint,
        ),
        SkillDefinition(
            name="set_mem_breakpoint", description="Set memory breakpoint on address range",
            args_schema={"address": "int/hex", "size": "int", "access_type": "read/write/access"},
            category="breakpoints", execute=skill_set_memory_breakpoint,
        ),
        SkillDefinition(
            name="delete_breakpoint", description="Delete breakpoint at address",
            args_schema={"address": "int/hex"},
            category="breakpoints", execute=skill_delete_breakpoint,
        ),
        SkillDefinition(
            name="set_conditional_bp", description="Set breakpoint with condition and optional logging",
            args_schema={"address": "int/hex", "condition": "expression", "log": "log format string"},
            category="breakpoints", execute=skill_set_conditional_breakpoint,
        ),
        SkillDefinition(
            name="bp_on_api_group", description="Set breakpoints on API group (memory/process/file/network/inject/crypto/bossix)",
            args_schema={"group": "API group name"},
            category="breakpoints", execute=skill_bp_on_api,
        ),
    ]
    for s in skills:
        registry.register(s)
