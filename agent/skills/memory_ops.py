"""
Memory Operation Skills — read, write, search, map, allocate.
"""

from . import SkillDefinition, SkillResult, SkillRegistry, parse_address


async def skill_read_memory(bridge, context, args):
    """Read memory at address."""
    address = args.get("address")
    size = args.get("size", 256)
    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    address = parse_address(address)

    data = await bridge.read_memory(address, size)
    if data is None:
        return SkillResult(success=False, summary=f"Failed to read memory at 0x{address:X}")

    # Format as hex dump
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  0x{address + offset:X}: {hex_part:<48s} {ascii_part}")

    return SkillResult(
        success=True,
        data=data.hex(),
        summary=f"Read {len(data)} bytes from 0x{address:X}",
        details="\n".join(lines),
    )


async def skill_write_memory(bridge, context, args):
    """Write data to memory."""
    address = args.get("address")
    data_hex = args.get("data", "")
    if address is None or not data_hex:
        return SkillResult(success=False, summary="Missing 'address' or 'data' argument")

    address = parse_address(address)

    data = bytes.fromhex(data_hex)
    success = await bridge.write_memory(address, data)
    return SkillResult(
        success=success,
        summary=f"{'Wrote' if success else 'Failed to write'} {len(data)} bytes to 0x{address:X}",
    )


async def skill_read_string(bridge, context, args):
    """Read null-terminated string from memory."""
    address = args.get("address")
    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    address = parse_address(address)

    string = await bridge.read_memory_string(address, args.get("max_len", 256))
    if string is None:
        return SkillResult(success=False, summary=f"Failed to read string at 0x{address:X}")

    return SkillResult(
        success=True,
        data=string,
        summary=f"String at 0x{address:X}: \"{string[:100]}{'...' if len(string) > 100 else ''}\"",
    )


async def skill_get_memory_map(bridge, context, args):
    """Get virtual memory map of the process."""
    regions = await bridge.get_memory_map()
    if not regions:
        return SkillResult(success=False, summary="Failed to get memory map")

    lines = [f"{'Base':>18s}  {'Size':>10s}  {'Protect':>10s}  {'Type':>8s}  Info"]
    lines.append("-" * 70)

    rwx_regions = []
    for r in regions:
        base = r.get("base", 0)
        size = r.get("size", 0)
        protect = r.get("protect", "")
        region_type = r.get("type", "")
        info = r.get("info", "")

        lines.append(f"  0x{base:016X}  {size:>10d}  {protect:>10s}  {region_type:>8s}  {info}")

        # Flag suspicious RWX regions
        if "RWX" in protect.upper() or "EXECUTE_READWRITE" in protect.upper():
            rwx_regions.append(f"0x{base:X} ({size} bytes)")

    summary = f"Memory map: {len(regions)} regions"
    if rwx_regions:
        summary += f"\n  ⚠ RWX regions found: {', '.join(rwx_regions)}"

    return SkillResult(
        success=True,
        data=regions,
        summary=summary,
        details="\n".join(lines),
        suggestions=["read_memory", "search_pattern"] if rwx_regions else [],
    )


async def skill_search_pattern(bridge, context, args):
    """Search for byte pattern in memory."""
    pattern = args.get("pattern", "")
    module = args.get("module")
    if not pattern:
        return SkillResult(success=False, summary="Missing 'pattern' argument")

    results = await bridge.search_pattern(pattern, module)
    if not results:
        return SkillResult(
            success=True, data=[],
            summary=f"Pattern '{pattern}' not found",
        )

    lines = [f"Found {len(results)} matches for '{pattern}':"]
    for r in results[:20]:
        addr = r.get("address", 0)
        mod = r.get("module", "")
        lines.append(f"  0x{addr:X} [{mod}]")

    if len(results) > 20:
        lines.append(f"  ... and {len(results) - 20} more")

    return SkillResult(
        success=True,
        data=results,
        summary=lines[0],
        details="\n".join(lines),
        suggestions=["disassemble", "read_memory", "set_breakpoint"],
    )


async def skill_search_strings(bridge, context, args):
    """Search for readable strings in the process."""
    min_length = args.get("min_length", 4)
    strings = await bridge.search_strings(min_length)

    if not strings:
        return SkillResult(success=True, data=[], summary="No strings found")

    # Categorize interesting strings
    interesting = {"urls": [], "paths": [], "registry": [], "apis": [], "other": []}
    for s in strings:
        text = s.get("text", "")
        if "http" in text.lower() or "://" in text:
            interesting["urls"].append(s)
        elif "\\" in text and (":" in text or text.startswith("\\\\")):
            interesting["paths"].append(s)
        elif "HKEY" in text or "SOFTWARE\\" in text:
            interesting["registry"].append(s)
        elif text.endswith("A") or text.endswith("W"):  # Possible API names
            interesting["apis"].append(s)
        else:
            interesting["other"].append(s)

    lines = [f"Found {len(strings)} strings (min length: {min_length}):"]
    for category, items in interesting.items():
        if items:
            lines.append(f"\n  [{category.upper()}] ({len(items)} found):")
            for item in items[:10]:
                addr = item.get("address", 0)
                text = item.get("text", "")[:80]
                lines.append(f"    0x{addr:X}: \"{text}\"")

    # Update context
    context.known_strings = strings

    return SkillResult(
        success=True,
        data=interesting,
        summary=f"Found {len(strings)} strings",
        details="\n".join(lines),
        suggestions=["read_string", "set_breakpoint"],
    )


async def skill_allocate_memory(bridge, context, args):
    """Allocate memory in target process."""
    size = args.get("size", 4096)
    protection = args.get("protection", 0x04)  # PAGE_READWRITE

    address = await bridge.allocate_memory(size, protection)
    if address is None:
        return SkillResult(success=False, summary="Failed to allocate memory")

    return SkillResult(
        success=True,
        data={"address": address, "size": size},
        summary=f"Allocated {size} bytes at 0x{address:X}",
    )


def register_memory_skills(registry: SkillRegistry):
    skills = [
        SkillDefinition(
            name="read_memory", description="Read memory at address (hex dump)",
            args_schema={"address": "int/hex", "size": "int (default 256)"},
            category="memory", execute=skill_read_memory,
        ),
        SkillDefinition(
            name="write_memory", description="Write hex data to memory",
            args_schema={"address": "int/hex", "data": "hex string"},
            category="memory", execute=skill_write_memory,
        ),
        SkillDefinition(
            name="read_string", description="Read null-terminated string from memory",
            args_schema={"address": "int/hex"},
            category="memory", execute=skill_read_string,
        ),
        SkillDefinition(
            name="get_memory_map", description="Get process virtual memory map (flags RWX sections)",
            category="memory", execute=skill_get_memory_map,
        ),
        SkillDefinition(
            name="search_pattern", description="Search for byte pattern in memory",
            args_schema={"pattern": "hex pattern with ?? wildcards", "module": "optional module name"},
            category="memory", execute=skill_search_pattern,
        ),
        SkillDefinition(
            name="search_strings", description="Find readable strings in process memory",
            args_schema={"min_length": "int (default 4)"},
            category="memory", execute=skill_search_strings,
        ),
        SkillDefinition(
            name="allocate_memory", description="Allocate memory in target process",
            args_schema={"size": "int", "protection": "int (default PAGE_READWRITE)"},
            category="memory", execute=skill_allocate_memory,
        ),
    ]
    for s in skills:
        registry.register(s)
