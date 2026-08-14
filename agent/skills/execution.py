"""
Execution Control Skills — run, step, pause, trace.
"""

from . import SkillDefinition, SkillResult, SkillRegistry, parse_address, parse_int


async def skill_run(bridge, context, args):
    result = await bridge.run()
    return SkillResult(
        success="error" not in result,
        data=result,
        summary="Resumed execution — process is running. Call get_registers after it breaks to see where it stopped."
                if "error" not in result else f"Run failed: {result.get('error')}",
        suggestions=["get_registers", "disassemble", "get_call_stack"],
    )


async def skill_pause(bridge, context, args):
    result = await bridge.pause()
    return SkillResult(
        success="error" not in result,
        data=result,
        summary="Paused execution" if "error" not in result else f"Pause failed: {result.get('error')}",
    )


async def skill_step_into(bridge, context, args):
    result = await bridge.step_into()
    # After stepping, get the new instruction
    regs = await bridge.get_registers()
    rip = regs.get("rip", 0) if regs else 0
    disasm = await bridge.disassemble(rip, 1) if rip else []
    instr = disasm[0] if disasm else {}

    return SkillResult(
        success="error" not in result,
        data={"result": result, "rip": rip, "instruction": instr},
        summary=f"Stepped into: 0x{rip:X} — {instr.get('mnemonic', '?')} {instr.get('operands', '')}",
        suggestions=["step_into", "step_over", "get_registers", "disassemble"],
    )


async def skill_step_over(bridge, context, args):
    result = await bridge.step_over()
    regs = await bridge.get_registers()
    rip = regs.get("rip", 0) if regs else 0
    disasm = await bridge.disassemble(rip, 1) if rip else []
    instr = disasm[0] if disasm else {}

    return SkillResult(
        success="error" not in result,
        data={"result": result, "rip": rip, "instruction": instr},
        summary=f"Stepped over: 0x{rip:X} — {instr.get('mnemonic', '?')} {instr.get('operands', '')}",
        suggestions=["step_into", "step_over", "get_registers"],
    )


async def skill_step_n(bridge, context, args):
    """Step N times and report final state."""
    count = parse_int(args.get("count", 10), 10)
    step_type = args.get("type", "over")  # "into" or "over"
    step_fn = bridge.step_into if step_type == "into" else bridge.step_over

    trace = []
    prev_rip = 0
    stuck_count = 0
    for i in range(count):
        result = await step_fn()
        if "error" in result:
            trace.append({
                "step": i + 1,
                "rip": "???",
                "instruction": f"[STOPPED: {result.get('error', 'unknown error')}]",
            })
            break

        regs = await bridge.get_registers()
        rip = regs.get("rip", 0) if regs else 0

        # Detect if process is stuck (same RIP for 3+ steps)
        if rip == prev_rip:
            stuck_count += 1
            if stuck_count >= 3:
                trace.append({
                    "step": i + 1,
                    "rip": f"0x{rip:X}",
                    "instruction": "[STUCK — RIP not advancing, process may have terminated]",
                })
                break
        else:
            stuck_count = 0
        prev_rip = rip

        disasm = await bridge.disassemble(rip, 1) if rip else []
        instr = disasm[0] if disasm else {}
        trace.append({
            "step": i + 1,
            "rip": f"0x{rip:X}",
            "instruction": f"{instr.get('mnemonic', '?')} {instr.get('operands', '')}",
        })

    trace_text = "\n".join(f"  {t['step']:3d}. {t['rip']}: {t['instruction']}" for t in trace)
    return SkillResult(
        success=True,
        data=trace,
        summary=f"Traced {len(trace)}/{count} steps ({step_type}):",
        details=trace_text,
    )


async def skill_run_to(bridge, context, args):
    """Run until a specific address."""
    address = args.get("address")
    if address is None:
        return SkillResult(success=False, summary="Missing 'address' argument")

    address = parse_address(address)

    # Set temporary breakpoint
    await bridge.set_breakpoint(address, bp_type="software")
    result = await bridge.run()

    # Check if we hit the target
    regs = await bridge.get_registers()
    rip = regs.get("rip", 0) if regs else 0

    # Clean up temp breakpoint
    await bridge.delete_breakpoint(address)

    hit_target = rip == address
    return SkillResult(
        success=hit_target,
        data={"rip": rip, "target": address, "hit": hit_target},
        summary=f"{'Hit target' if hit_target else 'Stopped at'} 0x{rip:X} (target was 0x{address:X})",
        suggestions=["disassemble", "get_registers", "get_call_stack"],
    )


async def skill_get_registers(bridge, context, args):
    """Get all CPU registers."""
    regs = await bridge.get_registers()
    if not regs:
        return SkillResult(success=False, summary="Failed to get registers")

    # Format nicely
    gpr_names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
    flag_names = ["cf", "zf", "sf", "of", "pf", "af", "df", "tf"]

    lines = ["General Purpose Registers:"]
    for name in gpr_names:
        if name in regs:
            lines.append(f"  {name:>3s} = 0x{regs[name]:016X}")

    lines.append("\nFlags:")
    for name in flag_names:
        if name in regs:
            lines.append(f"  {name:>2s} = {regs[name]}")

    # Update context
    context.current_rip = regs.get("rip", 0)

    return SkillResult(
        success=True,
        data=regs,
        summary=f"RIP=0x{regs.get('rip', 0):X} RSP=0x{regs.get('rsp', 0):X}",
        details="\n".join(lines),
    )


async def skill_set_register(bridge, context, args):
    """Set a CPU register to a specific value."""
    register = args.get("register", "")
    value = args.get("value", "")
    if not register or value == "":
        return SkillResult(
            success=False,
            summary="Missing 'register' or 'value' argument",
            error_code="MISSING_ARGUMENT",
            error_hint="Example: {\"register\": \"rax\", \"value\": \"0x0\"}",
        )

    value = parse_int(value)

    cmd = f"{register}={value:#x}"
    result = await bridge.execute_command(cmd)

    regs = await bridge.get_registers()
    actual = regs.get(register.lower(), "?") if regs else "?"

    return SkillResult(
        success="error" not in result,
        data={"register": register, "value": value, "actual": actual},
        summary=f"Set {register.upper()} = 0x{value:X}" + (f" (verified: 0x{actual:X})" if isinstance(actual, int) else ""),
        suggestions=["get_registers", "disassemble"],
    )


async def skill_execute_command(bridge, context, args):
    """Execute raw x64dbg command."""
    command = args.get("command", "")
    if not command:
        return SkillResult(success=False, summary="Missing 'command' argument")

    result = await bridge.execute_command(command)
    return SkillResult(
        success="error" not in result,
        data=result,
        summary=f"Executed: {command}",
        details=result.get("output", ""),
    )


def register_execution_skills(registry: SkillRegistry):
    skills = [
        SkillDefinition(
            name="run", description="Resume debugged process execution",
            category="execution", execute=skill_run,
        ),
        SkillDefinition(
            name="pause", description="Pause debugged process",
            category="execution", execute=skill_pause,
        ),
        SkillDefinition(
            name="step_into", description="Single step into (follow calls)",
            category="execution", execute=skill_step_into,
        ),
        SkillDefinition(
            name="step_over", description="Single step over (skip calls)",
            category="execution", execute=skill_step_over,
        ),
        SkillDefinition(
            name="step_n",
            description="Step N times and trace execution",
            args_schema={"count": "int (default 10)", "type": "'into' or 'over'"},
            category="execution", execute=skill_step_n,
        ),
        SkillDefinition(
            name="run_to",
            description="Run until specific address (temp breakpoint)",
            args_schema={"address": "int or hex string"},
            category="execution", execute=skill_run_to,
        ),
        SkillDefinition(
            name="get_registers", description="Get all CPU registers",
            category="execution", execute=skill_get_registers,
        ),
        SkillDefinition(
            name="set_register", description="Set a CPU register to a value",
            args_schema={"register": "register name", "value": "int or hex string"},
            category="execution", execute=skill_set_register,
        ),
        SkillDefinition(
            name="execute_command", description="Execute raw x64dbg command",
            args_schema={"command": "string"},
            category="execution", execute=skill_execute_command,
        ),
    ]
    for s in skills:
        registry.register(s)
