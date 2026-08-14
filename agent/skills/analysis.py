"""
Analysis Skills — disassembly, xrefs, function analysis, modules.

These skills do more than just call APIs — they POST-PROCESS results
to give the agent meaningful, actionable intelligence.
"""

from . import SkillDefinition, SkillResult, SkillRegistry, parse_address, parse_int


async def skill_disassemble(bridge, context, args):
    """Disassemble instructions at address."""
    address = args.get("address") or context.current_rip
    count = args.get("count", 30)

    if not address:
        return SkillResult(success=False, summary="No address specified and current RIP is unknown")
    address = parse_address(address)
    count = parse_int(count, 30)

    instructions = await bridge.disassemble(address, count)
    if not instructions:
        return SkillResult(success=False, summary=f"Failed to disassemble at 0x{address:X}")

    lines = []
    calls = []
    jumps = []
    for instr in instructions:
        addr = instr.get("address", 0)
        mnemonic = instr.get("mnemonic", "")
        operands = instr.get("operands", "")
        comment = instr.get("comment", "")
        hex_bytes = instr.get("bytes", "")

        line = f"  0x{addr:X}: {hex_bytes:<24s} {mnemonic:<8s} {operands}"
        if comment:
            line += f"  ; {comment}"
        lines.append(line)

        # Track control flow for analysis
        if mnemonic.lower().startswith("call"):
            calls.append({"address": addr, "target": operands})
        elif mnemonic.lower().startswith("j"):
            jumps.append({"address": addr, "target": operands, "type": mnemonic})

    analysis = []
    if calls:
        analysis.append(f"Calls found: {len(calls)}")
        for c in calls:
            analysis.append(f"  CALL at 0x{c['address']:X} -> {c['target']}")
    if jumps:
        analysis.append(f"Jumps found: {len(jumps)}")

    return SkillResult(
        success=True,
        data={"instructions": instructions, "calls": calls, "jumps": jumps},
        summary=f"Disassembled {len(instructions)} instructions from 0x{address:X}",
        details="\n".join(lines) + ("\n\n" + "\n".join(analysis) if analysis else ""),
        suggestions=["analyze_function", "get_xrefs", "set_breakpoint"],
    )


async def skill_analyze_function(bridge, context, args):
    """Analyze a function — disassembly, xrefs, CFG info."""
    address = args.get("address") or context.current_rip
    if not address:
        return SkillResult(success=False, summary="No address specified and current RIP is unknown")
    address = parse_address(address)

    # Get function analysis from x64dbg
    func_info = await bridge.analyze_function(address)
    if "error" in func_info:
        return SkillResult(success=False, summary=f"Failed to analyze function at 0x{address:X}")

    # Also get disassembly and xrefs
    disasm = await bridge.disassemble(address, 50)
    xrefs_to = await bridge.get_xrefs_to(address)
    xrefs_from = await bridge.get_xrefs_from(address)

    # Build analysis report
    func_name = func_info.get("name", f"sub_{address:X}")
    func_size = func_info.get("size", 0)
    func_end = func_info.get("end", address + func_size)

    lines = [
        f"Function: {func_name}",
        f"  Address: 0x{address:X} — 0x{func_end:X} ({func_size} bytes)",
    ]

    # Analyze the disassembly for patterns
    api_calls = []
    string_refs = []
    crypto_indicators = []
    for instr in disasm:
        mnemonic = instr.get("mnemonic", "").lower()
        operands = instr.get("operands", "")
        comment = instr.get("comment", "")

        if mnemonic == "call" and comment:
            api_calls.append(comment)
        if any(kw in comment.lower() for kw in ["str:", "string:", "\""]):
            string_refs.append(comment)
        if mnemonic in ("xor", "rol", "ror", "shl", "shr") and operands:
            crypto_indicators.append(f"{mnemonic} {operands}")

    if api_calls:
        lines.append(f"\n  API Calls ({len(api_calls)}):")
        for api in api_calls:
            lines.append(f"    - {api}")

    if xrefs_to:
        lines.append(f"\n  Called from ({len(xrefs_to)} xrefs):")
        for xref in xrefs_to[:10]:
            lines.append(f"    - 0x{xref.get('address', 0):X}")

    if xrefs_from:
        lines.append(f"\n  Calls to ({len(xrefs_from)} xrefs):")
        for xref in xrefs_from[:10]:
            lines.append(f"    - 0x{xref.get('address', 0):X}")

    if crypto_indicators:
        lines.append(f"\n  Possible crypto operations:")
        for op in crypto_indicators[:5]:
            lines.append(f"    - {op}")

    if string_refs:
        lines.append(f"\n  String references:")
        for s in string_refs[:10]:
            lines.append(f"    - {s}")

    # Store in context
    context.known_functions[address] = {
        "name": func_name,
        "size": func_size,
        "api_calls": api_calls,
        "xrefs_to": len(xrefs_to),
        "xrefs_from": len(xrefs_from),
    }

    return SkillResult(
        success=True,
        data=func_info,
        summary=f"Analyzed {func_name} at 0x{address:X} ({func_size} bytes, {len(api_calls)} API calls)",
        details="\n".join(lines),
        suggestions=["disassemble", "get_xrefs", "set_breakpoint"],
    )


async def skill_get_xrefs(bridge, context, args):
    """Get cross-references to/from an address."""
    address = args.get("address")
    direction = args.get("direction", "to")  # "to" or "from"

    address = parse_address(address)

    if direction == "to":
        xrefs = await bridge.get_xrefs_to(address)
    else:
        xrefs = await bridge.get_xrefs_from(address)

    if not xrefs:
        return SkillResult(
            success=True, data=[],
            summary=f"No xrefs {direction} 0x{address:X}",
        )

    lines = [f"Cross-references {direction} 0x{address:X}:"]
    for xref in xrefs:
        addr = xref.get("address", 0)
        ref_type = xref.get("type", "")
        lines.append(f"  0x{addr:X} [{ref_type}]")

    return SkillResult(
        success=True,
        data=xrefs,
        summary=f"{len(xrefs)} xrefs {direction} 0x{address:X}",
        details="\n".join(lines),
        suggestions=["disassemble", "analyze_function"],
    )


async def skill_get_modules(bridge, context, args):
    """List loaded modules."""
    modules = await bridge.get_modules()
    if not modules:
        return SkillResult(success=False, summary="Failed to get modules")

    lines = [f"{'Base':>18s}  {'Size':>10s}  {'Entry':>18s}  Name"]
    lines.append("-" * 70)
    for m in modules:
        base = m.get("base", 0)
        size = m.get("size", 0)
        entry = m.get("entry", 0)
        name = m.get("name", "")
        path = m.get("path", "")
        lines.append(f"  0x{base:016X}  {size:>10d}  0x{entry:016X}  {name}")

    return SkillResult(
        success=True,
        data=modules,
        summary=f"Loaded modules: {len(modules)}",
        details="\n".join(lines),
        suggestions=["get_imports", "get_exports", "disassemble"],
    )


async def skill_get_imports(bridge, context, args):
    """Get import table entries."""
    module = args.get("module")
    imports = await bridge.get_imports(module)
    if not imports:
        return SkillResult(success=True, data=[], summary="No imports found")

    # Group by DLL
    by_dll = {}
    for imp in imports:
        dll = imp.get("module", "unknown")
        by_dll.setdefault(dll, []).append(imp)

    lines = [f"Imports ({len(imports)} total):"]
    for dll, funcs in sorted(by_dll.items()):
        lines.append(f"\n  [{dll}] ({len(funcs)} functions):")
        for f in funcs[:15]:
            addr = f.get("address", 0)
            name = f.get("name", "")
            lines.append(f"    0x{addr:X}: {name}")
        if len(funcs) > 15:
            lines.append(f"    ... and {len(funcs) - 15} more")

    return SkillResult(
        success=True,
        data=imports,
        summary=f"Imports: {len(imports)} functions from {len(by_dll)} DLLs",
        details="\n".join(lines),
    )


async def skill_get_exports(bridge, context, args):
    """Get export table entries."""
    module = args.get("module")
    exports = await bridge.get_exports(module)
    if not exports:
        return SkillResult(success=True, data=[], summary="No exports found")

    lines = [f"Exports ({len(exports)} total):"]
    for exp in exports[:30]:
        addr = exp.get("address", 0)
        name = exp.get("name", "")
        ordinal = exp.get("ordinal", 0)
        lines.append(f"  0x{addr:X}: {name} (ordinal {ordinal})")
    if len(exports) > 30:
        lines.append(f"  ... and {len(exports) - 30} more")

    return SkillResult(
        success=True,
        data=exports,
        summary=f"Exports: {len(exports)} functions",
        details="\n".join(lines),
    )


async def skill_get_call_stack(bridge, context, args):
    """Get current call stack."""
    frames = await bridge.get_call_stack()
    if not frames:
        return SkillResult(success=False, summary="Failed to get call stack")

    lines = ["Call Stack:"]
    for i, frame in enumerate(frames):
        addr = frame.get("address", 0)
        ret_addr = frame.get("return_address", 0)
        module = frame.get("module", "")
        func = frame.get("function", "")
        lines.append(f"  #{i}: 0x{addr:X} [{module}!{func}] -> ret 0x{ret_addr:X}")

    context.call_stack = frames

    return SkillResult(
        success=True,
        data=frames,
        summary=f"Call stack: {len(frames)} frames",
        details="\n".join(lines),
        suggestions=["disassemble", "analyze_function"],
    )


async def skill_evaluate(bridge, context, args):
    """Evaluate x64dbg expression."""
    expression = args.get("expression", "")
    if not expression:
        return SkillResult(success=False, summary="Missing 'expression' argument")

    value = await bridge.evaluate_expression(expression)
    if value is None:
        return SkillResult(success=False, summary=f"Failed to evaluate: {expression}")

    return SkillResult(
        success=True,
        data=value,
        summary=f"{expression} = 0x{value:X} ({value})",
    )


def register_analysis_skills(registry: SkillRegistry):
    skills = [
        SkillDefinition(
            name="disassemble", description="Disassemble instructions at address with call/jump analysis",
            args_schema={"address": "int/hex (default: RIP)", "count": "int (default 30)"},
            category="analysis", execute=skill_disassemble,
        ),
        SkillDefinition(
            name="analyze_function", description="Deep function analysis — disasm, xrefs, API calls, patterns",
            args_schema={"address": "int/hex"},
            category="analysis", execute=skill_analyze_function,
        ),
        SkillDefinition(
            name="get_xrefs", description="Get cross-references to/from address",
            args_schema={"address": "int/hex", "direction": "'to' or 'from'"},
            category="analysis", execute=skill_get_xrefs,
        ),
        SkillDefinition(
            name="get_modules", description="List loaded modules with base addresses",
            category="analysis", execute=skill_get_modules,
        ),
        SkillDefinition(
            name="get_imports", description="Get import table (grouped by DLL)",
            args_schema={"module": "optional module name"},
            category="analysis", execute=skill_get_imports,
        ),
        SkillDefinition(
            name="get_exports", description="Get export table",
            args_schema={"module": "optional module name"},
            category="analysis", execute=skill_get_exports,
        ),
        SkillDefinition(
            name="get_call_stack", description="Get current call stack frames",
            category="analysis", execute=skill_get_call_stack,
        ),
        SkillDefinition(
            name="evaluate", description="Evaluate x64dbg expression",
            args_schema={"expression": "string"},
            category="analysis", execute=skill_evaluate,
        ),
    ]
    for s in skills:
        registry.register(s)
