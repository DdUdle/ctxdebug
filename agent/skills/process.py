"""
Process Skills — threads, handles, PEB, modules, dumping.
"""

from . import SkillDefinition, SkillResult, SkillRegistry


async def skill_get_process_info(bridge, context, args):
    """Get comprehensive process information."""
    modules = await bridge.get_modules()
    threads = await bridge.get_threads()
    peb = await bridge.get_peb()

    lines = []

    # Main module info
    if modules:
        main = modules[0]
        context.target_process = main.get("name", "unknown")
        context.base_address = main.get("base", 0)
        lines.append(f"Target: {main.get('name', '?')}")
        lines.append(f"  Path: {main.get('path', '?')}")
        lines.append(f"  Base: 0x{main.get('base', 0):X}")
        lines.append(f"  Size: {main.get('size', 0)}")
        lines.append(f"  Entry: 0x{main.get('entry', 0):X}")

    # PEB info
    if peb and "error" not in peb:
        lines.append(f"\nPEB at 0x{peb.get('address', 0):X}:")
        lines.append(f"  BeingDebugged: {peb.get('being_debugged', '?')}")
        lines.append(f"  ImageBase: 0x{peb.get('image_base', 0):X}")
        lines.append(f"  NtGlobalFlag: 0x{peb.get('nt_global_flag', 0):X}")
        context.target_pid = peb.get("pid")

    # Thread summary
    if threads:
        lines.append(f"\nThreads: {len(threads)}")
        for t in threads[:5]:
            tid = t.get("id", 0)
            entry = t.get("entry", 0)
            state = t.get("state", "")
            lines.append(f"  TID {tid}: entry=0x{entry:X} state={state}")

    # Module count
    if modules:
        lines.append(f"\nLoaded modules: {len(modules)}")

    return SkillResult(
        success=True,
        data={"modules": modules, "threads": threads, "peb": peb},
        summary=f"Process: {context.target_process or '?'} (base=0x{context.base_address:X})",
        details="\n".join(lines),
        suggestions=["get_imports", "get_memory_map", "disassemble"],
    )


async def skill_get_threads(bridge, context, args):
    """List process threads."""
    threads = await bridge.get_threads()
    if not threads:
        return SkillResult(success=False, summary="Failed to get threads")

    lines = ["Threads:"]
    for t in threads:
        tid = t.get("id", 0)
        entry = t.get("entry", 0)
        state = t.get("state", "")
        priority = t.get("priority", "")
        name = t.get("name", "")
        line = f"  TID {tid}: entry=0x{entry:X} state={state}"
        if priority:
            line += f" priority={priority}"
        if name:
            line += f" ({name})"
        lines.append(line)

    return SkillResult(
        success=True,
        data=threads,
        summary=f"Threads: {len(threads)}",
        details="\n".join(lines),
    )


async def skill_get_peb_info(bridge, context, args):
    """Get detailed PEB information."""
    peb = await bridge.get_peb()
    if not peb or "error" in peb:
        return SkillResult(success=False, summary="Failed to get PEB")

    lines = [f"Process Environment Block (PEB):"]
    for key, value in peb.items():
        if isinstance(value, int) and value > 0xFFFF:
            lines.append(f"  {key}: 0x{value:X}")
        else:
            lines.append(f"  {key}: {value}")

    # Detect anti-debug red flags
    warnings = []
    if peb.get("being_debugged"):
        warnings.append("BeingDebugged flag is set (IsDebuggerPresent will return TRUE)")
    nt_flag = peb.get("nt_global_flag", 0)
    if nt_flag & 0x70:
        warnings.append(f"NtGlobalFlag=0x{nt_flag:X} — debug flags set (FLG_HEAP_*)")

    if warnings:
        lines.append("\nBossix warnings:")
        for w in warnings:
            lines.append(f"  ! {w}")

    return SkillResult(
        success=True,
        data=peb,
        summary=f"PEB at 0x{peb.get('address', 0):X}",
        details="\n".join(lines),
        suggestions=["hide_bossix"] if warnings else [],
    )


async def skill_get_handles(bridge, context, args):
    """List process handles."""
    handles = await bridge.get_handles()
    if not handles:
        return SkillResult(success=True, data=[], summary="No handles or failed to enumerate")

    # Group by type
    by_type = {}
    for h in handles:
        h_type = h.get("type", "Unknown")
        by_type.setdefault(h_type, []).append(h)

    lines = [f"Handles ({len(handles)} total):"]
    for h_type, items in sorted(by_type.items()):
        lines.append(f"\n  [{h_type}] ({len(items)}):")
        for item in items[:10]:
            handle_val = item.get("handle", 0)
            name = item.get("name", "")
            lines.append(f"    0x{handle_val:X}: {name}")
        if len(items) > 10:
            lines.append(f"    ... and {len(items) - 10} more")

    return SkillResult(
        success=True,
        data=handles,
        summary=f"Handles: {len(handles)} total, {len(by_type)} types",
        details="\n".join(lines),
    )


async def skill_dump_module(bridge, context, args):
    """Dump a module to disk."""
    module = args.get("module", "")
    output = args.get("output", "")

    if not module:
        return SkillResult(success=False, summary="Missing 'module' argument")
    if not output:
        output = f"{module}_dump.exe"

    success = await bridge.dump_module(module, output)
    return SkillResult(
        success=success,
        summary=f"{'Dumped' if success else 'Failed to dump'} {module} to {output}",
    )


async def skill_run_script(bridge, context, args):
    """Run x64dbg script."""
    script = args.get("script", "")
    if not script:
        return SkillResult(success=False, summary="Missing 'script' argument")

    result = await bridge.run_script(script)
    return SkillResult(
        success="error" not in result,
        data=result,
        summary=f"Script executed",
        details=result.get("output", ""),
    )


def register_process_skills(registry: SkillRegistry):
    skills = [
        SkillDefinition(
            name="get_process_info", description="Get comprehensive process info (modules, threads, PEB)",
            category="process", execute=skill_get_process_info,
        ),
        SkillDefinition(
            name="get_threads", description="List process threads",
            category="process", execute=skill_get_threads,
        ),
        SkillDefinition(
            name="get_peb_info", description="Get PEB info with anti-debug flag detection",
            category="process", execute=skill_get_peb_info,
        ),
        SkillDefinition(
            name="get_handles", description="List process handles (grouped by type)",
            category="process", execute=skill_get_handles,
        ),
        SkillDefinition(
            name="dump_module", description="Dump module to disk",
            args_schema={"module": "module name", "output": "output path"},
            category="process", execute=skill_dump_module,
        ),
        SkillDefinition(
            name="run_script", description="Execute x64dbg script commands",
            args_schema={"script": "script text"},
            category="process", execute=skill_run_script,
        ),
    ]
    for s in skills:
        registry.register(s)
