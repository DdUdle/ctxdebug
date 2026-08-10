"""
MCP Server — stdio transport for Claude Desktop / Cursor / Claude Code integration.

This MCP server is OPTIMIZED for AI model consumption:

1. Tool descriptions are detailed with usage examples and "WHEN TO USE" guidance.
2. Schemas use proper JSON types (integer/number/boolean), not just string.
3. Enum constraints on known values (API groups, breakpoint types, step types).
4. Structured JSON responses via SkillResult.to_json() — no narrative parsing.
5. Tools are CONSOLIDATED into ~25 domain-oriented tools (vs 30+ granular).
6. Errors include machine-readable codes + actionable hints.
7. outputSchema declared so models know the response shape.

Key differences from existing x64dbg MCP servers:
- Agent-powered responses — results include analysis and suggestions
- Session context — the server maintains debugging state across calls
- Pattern recognition — automatically identifies interesting patterns
- Memory — recalls relevant info from past sessions
"""

import asyncio
import json
import sys
from typing import Any


# ----------------------------------------------------------------------
# Schema fragments — DRY across tool definitions
# ----------------------------------------------------------------------
_HEX_ADDRESS = {
    "type": "string",
    "description": "Memory address as hex string. ALWAYS use '0x' prefix. "
                   "Examples: '0x401000', '0x7FFE0308', '0x00007FF7C0001234'. "
                   "WARNING: without '0x' prefix, '401000' is treated as decimal 401000, not hex 0x401000.",
}

_HEX_ADDRESS_OPT = {
    **_HEX_ADDRESS,
    "description": _HEX_ADDRESS["description"] + " If omitted, current RIP is used.",
}

_STANDARD_OUTPUT = {
    "type": "object",
    "properties": {
        "success": {"type": "boolean"},
        "summary": {"type": "string", "description": "One-line human-readable result"},
        "data": {"description": "Structured result data (varies by tool)"},
        "details": {"type": "string", "description": "Detailed text breakdown"},
        "suggested_next_tools": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Tools recommended to call next based on this result",
        },
        "error": {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "message": {"type": "string"},
                "hint": {"type": "string", "description": "Actionable suggestion to fix the error"},
            },
        },
    },
    "required": ["success", "summary"],
}


def _arg(args: dict, key: str, default=None):
    """Null-safe arg getter. Returns default if key is missing OR value is None.

    Some MCP runtimes send `null` for omitted optional fields instead of
    omitting the key entirely. `dict.get(key, default)` returns `None`
    (not default) when the key is present with value `None`.
    """
    val = args.get(key)
    return val if val is not None else default


def _tool(name: str, description: str, properties: dict, required: list = None,
         output_schema: dict = None) -> dict:
    """Helper to build an MCP tool definition with proper schema."""
    tool = {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": False,
        },
    }
    if output_schema:
        tool["outputSchema"] = output_schema
    return tool


class MCPServer:
    """
    Model Context Protocol server with stdio transport.

    Implements MCP 2024-11-05 spec with:
    - tools (debugging operations)
    - resources (debugger state, memory, patterns)
    - prompts (pre-built analysis workflows)
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "x64-ai-debugger"
    SERVER_VERSION = "0.2.0"

    def __init__(self, agent):
        self.agent = agent
        self._request_id = 0
        self._running = False

    # ------------------------------------------------------------------
    # Tool catalogue — exposed to the AI model
    # ------------------------------------------------------------------
    def _get_tools(self) -> list[dict]:
        return [
            # =====================================================
            # AGENT META-TOOLS — high-level autonomous operations
            # =====================================================
            _tool(
                "agent_analyze",
                "AUTONOMOUS ANALYSIS: Ask the AI agent to plan, execute, and report on a debugging goal. "
                "The agent runs a ReAct loop, calls multiple debugging skills, and returns findings. "
                "USE WHEN: open-ended exploration — 'find unpacking loop', 'identify anti-debug', "
                "'trace execution from main'. "
                "DO NOT USE for single specific operations — call the dedicated tool instead.",
                {
                    "goal": {
                        "type": "string",
                        "minLength": 5,
                        "description": "Goal in plain English. Be specific. Examples: "
                                       "'Find all VirtualAlloc call sites and identify the unpacking loop', "
                                       "'Locate anti-debug checks and suggest patches', "
                                       "'Trace 50 instructions from RIP and summarize control flow'.",
                    },
                    "max_steps": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "default": 15,
                        "description": "Max reasoning steps. 5-10 focused, 15-25 exploration, 30+ complex.",
                    },
                },
                required=["goal"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "agent_get_context",
                "Get the agent's current debugging context: target process, current RIP, breakpoints, "
                "discovered functions, found patterns, current goal. "
                "USE WHEN: you need to know what the agent already knows before deciding next steps.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "memory_recall",
                "Recall insights from past debugging sessions. Searches the agent's persistent memory "
                "(~/.x64ai/) for matching patterns and insights. "
                "USE WHEN: starting analysis on a new binary — past insights may apply.",
                {
                    "query": {
                        "type": "string",
                        "description": "Examples: 'unpacking techniques', 'crypto patterns', 'IsDebuggerPresent'.",
                    },
                },
                required=["query"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "list_known_patterns",
                "List the agent's known binary patterns: packer signatures, anti-debug checks, "
                "crypto routines, syscall stubs, Heaven's Gate, etc. "
                "USE WHEN: deciding what to search for, or to understand what the agent recognizes.",
                {
                    "category": {
                        "type": "string",
                        "enum": ["packer", "anti-debug", "crypto", "evasion", "obfuscation", "inject", "syscall", "all"],
                        "default": "all",
                    },
                },
                output_schema=_STANDARD_OUTPUT,
            ),

            # =====================================================
            # EXECUTION CONTROL
            # =====================================================
            _tool(
                "execution_control",
                "Control execution: run, pause, single-step, run-to-address. "
                "TIP: Use 'run_to' instead of breakpoint(action='set')+run for one-shot stops (auto-cleans the BP).",
                {
                    "action": {
                        "type": "string",
                        "enum": ["run", "pause", "step_into", "step_over", "step_n", "run_to"],
                        "description": "run = resume; pause = halt; step_into follows CALL; "
                                       "step_over skips CALLs; step_n traces N instructions with stuck-detection; "
                                       "run_to = run until address (uses temp breakpoint).",
                    },
                    "count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10000,
                        "default": 10,
                        "description": "For 'step_n': number of steps.",
                    },
                    "step_type": {
                        "type": "string",
                        "enum": ["into", "over"],
                        "default": "over",
                        "description": "For 'step_n': step into CALLs or over them.",
                    },
                    "address": {
                        **_HEX_ADDRESS,
                        "description": "For 'run_to': target address. Example: '0x401234'.",
                    },
                },
                required=["action"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "get_registers",
                "Get all CPU registers (GPRs + flags + RIP/RSP). Updates the agent's current_rip context.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "set_register",
                "Set a CPU register to a specific value. Useful for bypassing checks (set RAX=0 after "
                "IsDebuggerPresent), redirecting execution (change RIP), or modifying function arguments.",
                {
                    "register": {
                        "type": "string",
                        "enum": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
                                 "eax", "ebx", "ecx", "edx"],
                        "description": "Register name (case-insensitive).",
                    },
                    "value": {
                        "type": "string",
                        "description": "Value to set. Use '0x' prefix for hex. Examples: '0x0', '0x401000', '0'.",
                    },
                },
                required=["register", "value"],
                output_schema=_STANDARD_OUTPUT,
            ),

            # =====================================================
            # DISASSEMBLY & ANALYSIS
            # =====================================================
            _tool(
                "disassemble",
                "Disassemble instructions with auto call/jump analysis. Returns instructions plus "
                "categorized lists of CALLs and JMPs.",
                {
                    "address": _HEX_ADDRESS_OPT,
                    "count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 30,
                        "description": "5-10 = quick peek; 30-50 = function head; 100+ = full functions.",
                    },
                },
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "analyze_function",
                "Deep function analysis: disassembly, xrefs in/out, API calls, string refs, "
                "crypto indicators (xor/rol/ror/shl/shr).",
                {"address": _HEX_ADDRESS_OPT},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "get_xrefs",
                "Get cross-references to or from an address (callers / callees).",
                {
                    "address": _HEX_ADDRESS,
                    "direction": {
                        "type": "string",
                        "enum": ["to", "from"],
                        "default": "to",
                        "description": "'to' = who references this address; 'from' = what it references.",
                    },
                },
                required=["address"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "evaluate_expression",
                "Evaluate an x64dbg expression. Resolves API names, registers, arithmetic, pointer dereferences. "
                "TIP: Use [address] syntax to read a pointer value, e.g. '[rsp]' reads the QWORD at RSP. "
                "This is faster than read_memory for single values.",
                {
                    "expression": {
                        "type": "string",
                        "description": "x64dbg expression. Examples: 'IsDebuggerPresent', 'rcx', "
                                       "'kernel32.dll:VirtualAlloc', '[rsp]', 'rip + 0x100'.",
                    },
                },
                required=["expression"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "get_call_stack",
                "Get the current thread's call stack with module + function names per frame.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),

            # =====================================================
            # PROCESS / MODULES / IMPORTS
            # =====================================================
            _tool(
                "process_info",
                "Get comprehensive process info: main module, base address, entry point, threads, PEB. "
                "USE WHEN: starting analysis — typically the first call to orient yourself.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "list_modules",
                "List all loaded modules (DLLs/EXE) with bases, sizes, entry points.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "list_imports",
                "Get import table grouped by DLL. Network imports → C2; crypto imports → ransomware; "
                "anti-debug imports → evasion.",
                {
                    "module": {
                        "type": "string",
                        "description": "Optional module name. If omitted, uses main module.",
                    },
                },
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "list_exports",
                "Get the export table of a module — exported function names + addresses + ordinals.",
                {
                    "module": {
                        "type": "string",
                        "description": "Optional module name. If omitted, uses main module.",
                    },
                },
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "get_threads",
                "List threads with TID, entry, state, priority.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "get_peb",
                "Get FULL PEB (Process Environment Block) dump with anti-debug flag analysis. "
                "Returns ALL fields. Use process_info for a quick overview; use this for deep PEB inspection.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "get_handles",
                "List process handles grouped by type (File, Mutant, Event, Thread, etc.).",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),

            # =====================================================
            # MEMORY OPERATIONS
            # =====================================================
            _tool(
                "memory_map",
                "Get the process virtual memory map. AUTOMATICALLY FLAGS RWX regions (unpacking indicator).",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "read_memory",
                "Read memory and return as hex+ASCII dump.",
                {
                    "address": _HEX_ADDRESS,
                    "size": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65536,
                        "default": 256,
                        "description": "Bytes to read. 16-64 small structs, 256 buffer peek, 4096 full page.",
                    },
                },
                required=["address"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "write_memory",
                "Write hex bytes to memory. ⚠ Modifies process state.",
                {
                    "address": _HEX_ADDRESS,
                    "data": {
                        "type": "string",
                        "pattern": "^[0-9a-fA-F]+$",
                        "description": "Contiguous hex string WITHOUT spaces or 0x prefix. "
                                       "Example: '90909090' = 4x NOP. '4831C0' = xor rax,rax. "
                                       "NOTE: Unlike search_pattern which uses spaces between bytes, "
                                       "write_memory expects a solid hex string.",
                    },
                },
                required=["address", "data"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "read_string",
                "Read a null-terminated string from memory (ASCII).",
                {
                    "address": _HEX_ADDRESS,
                    "max_len": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 65536,
                        "default": 256,
                    },
                },
                required=["address"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "search_pattern",
                "Search memory for a byte pattern with ?? wildcards. "
                "Examples: 'CC' (INT3), '0F 31' (RDTSC), 'E9 ?? ?? ?? ??' (JMP rel32).",
                {
                    "pattern": {
                        "type": "string",
                        "description": "Hex bytes separated by spaces, '??' as wildcard. "
                                       "Examples: '90 90 90', 'E8 ?? ?? ?? ??', '48 89 ?? 24'.",
                    },
                    "module": {
                        "type": "string",
                        "description": "Optional module name to limit search scope (faster).",
                    },
                },
                required=["pattern"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "search_strings",
                "Find readable strings in ALL loaded modules, AUTO-CATEGORIZED into urls/paths/registry/apis/other. "
                "Great for IOCs and hardcoded URLs/paths. May be slow on large processes.",
                {
                    "min_length": {
                        "type": "integer",
                        "minimum": 3,
                        "maximum": 256,
                        "default": 4,
                        "description": "Lower = more matches but more noise.",
                    },
                },
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "allocate_memory",
                "Allocate memory in the target process. Returns the allocated address.",
                {
                    "size": {
                        "type": "integer",
                        "minimum": 1,
                        "default": 4096,
                        "description": "Allocation size in bytes (page-aligned).",
                    },
                    "protection": {
                        "type": "integer",
                        "default": 4,
                        "description": "Page protection as integer. 4 = PAGE_READWRITE (default), "
                                       "64 = PAGE_EXECUTE_READWRITE. Use 64 for executable shellcode.",
                    },
                },
                output_schema=_STANDARD_OUTPUT,
            ),

            # =====================================================
            # BREAKPOINTS — unified action-based tool
            # =====================================================
            _tool(
                "breakpoint",
                "Set, list, or delete a breakpoint. Supports software, hardware, memory, conditional, and API-by-name. "
                "USE 'set' WITH 'api' to break on an imported function by name (no need to resolve address). "
                "USE 'set_conditional' to break only when expression is true (e.g., 'rcx == 0x1000'). "
                "USE 'set_hw' for hardware breakpoints (no code modification, useful when scanning for INT3). "
                "USE 'list' to see all currently active breakpoints. "
                "For a single API, use action='set' + 'api'. For bulk API groups (all memory/network/etc.), "
                "use breakpoint_on_api_group instead.",
                {
                    "action": {
                        "type": "string",
                        "enum": ["set", "set_hw", "set_mem", "set_conditional", "delete", "list"],
                        "description": "set = software BP; set_hw = hardware BP; set_mem = memory access BP; "
                                       "set_conditional = software BP with condition; delete = remove BP; "
                                       "list = show all active breakpoints.",
                    },
                    "address": {
                        **_HEX_ADDRESS,
                        "description": _HEX_ADDRESS["description"] + " For 'set' you may use 'api' instead.",
                    },
                    "api": {
                        "type": "string",
                        "description": "API name (only for action='set'). Examples: 'IsDebuggerPresent', "
                                       "'kernel32.VirtualAlloc'.",
                    },
                    "hw_condition": {
                        "type": "string",
                        "enum": ["execute", "read", "write", "readwrite"],
                        "default": "execute",
                        "description": "For 'set_hw': what triggers the breakpoint.",
                    },
                    "size": {
                        "type": "integer",
                        "enum": [1, 2, 4, 8],
                        "default": 1,
                        "description": "For 'set_hw': 1 byte (default). "
                                       "For 'set_mem': use 4 (DWORD) or 8 (QWORD) — default 1 is rarely useful for memory watches.",
                    },
                    "mem_access": {
                        "type": "string",
                        "enum": ["read", "write", "access"],
                        "default": "write",
                        "description": "For 'set_mem': type of memory access.",
                    },
                    "condition": {
                        "type": "string",
                        "description": "For 'set_conditional': x64dbg expression. "
                                       "Example: 'rcx == 0x1000', 'rax > 0x100'.",
                    },
                    "log": {
                        "type": "string",
                        "description": "For 'set_conditional': log format string instead of breaking. "
                                       "Example: 'VirtualAlloc(size={rdx}, prot={r9:x})'.",
                    },
                },
                required=["action"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "breakpoint_on_api_group",
                "Set breakpoints on all APIs in a category at once. Saves many calls vs setting each manually.",
                {
                    "group": {
                        "type": "string",
                        "enum": ["memory", "process", "file", "registry", "network", "inject", "crypto", "anti-debug"],
                        "description": "memory: VirtualAlloc/Protect/Free, HeapAlloc/Free. "
                                       "process: CreateProcess/RemoteThread, OpenProcess. "
                                       "file: CreateFile/ReadFile/WriteFile/DeleteFile. "
                                       "registry: RegOpen/Set/QueryValueEx. "
                                       "network: connect/send/recv/InternetOpen/HttpOpenRequest. "
                                       "inject: WriteProcessMemory/CreateRemoteThread/QueueUserAPC. "
                                       "crypto: CryptEncrypt/Decrypt, BCrypt*. "
                                       "anti-debug: IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess.",
                    },
                },
                required=["group"],
                output_schema=_STANDARD_OUTPUT,
            ),

            # =====================================================
            # BOSSIX
            # =====================================================
            _tool(
                "bossix_scan",
                "COMPREHENSIVE bossix scan: PEB flags, API imports, byte patterns, RDTSC. "
                "Returns detected techniques + targeted bypass suggestions per finding.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "bossix_hide",
                "Hide debugger via PEB patches: zero BeingDebugged, clear NtGlobalFlag, x64dbg built-in hide.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "bossix_patch",
                "Auto-patch a bossix check at an address. Picks the right patch based on instruction: "
                "flips conditional jumps, NOPs test/cmp, replaces CALL with xor eax,eax.",
                {
                    "address": _HEX_ADDRESS,
                    "technique": {
                        "type": "string",
                        "description": "Optional technique name (informational; affects logging only).",
                    },
                },
                required=["address"],
                output_schema=_STANDARD_OUTPUT,
            ),

            # =====================================================
            # ADVANCED / RAW
            # =====================================================
            _tool(
                "execute_command",
                "Execute a raw x64dbg command. ESCAPE HATCH for operations not covered by other tools. "
                "USE SPARINGLY — prefer the dedicated tool when one exists.",
                {
                    "command": {
                        "type": "string",
                        "description": "Raw x64dbg command. See https://help.x64dbg.com/en/latest/commands/index.html. "
                                       "Examples: 'log \"hello\"', 'cmt 0x401000, \"my note\"', 'StepInto 5'.",
                    },
                },
                required=["command"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "dump_module",
                "Dump a loaded module to disk (post-unpacking, etc.).",
                {
                    "module": {
                        "type": "string",
                        "description": "Module name. Example: 'target.exe', 'w.dll'.",
                    },
                    "output": {
                        "type": "string",
                        "description": "Output path. If omitted, uses '<module>_dump.exe' in cwd.",
                    },
                },
                required=["module"],
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "run_script",
                "Execute a multi-line x64dbg script (commands run atomically). "
                "One command per line. Example: 'bp VirtualAlloc\\nrun\\nlog \"hit VirtualAlloc\"'.",
                {
                    "script": {
                        "type": "string",
                        "description": "Multi-line x64dbg script. One command per line, separated by \\n.",
                    },
                },
                required=["script"],
                output_schema=_STANDARD_OUTPUT,
            ),
            # =====================================================
            # LIFECYCLE — launch / status
            # =====================================================
            _tool(
                "x64dbg_launch",
                "Launch x64dbg debugger (with optional target EXE). "
                "USE WHEN: x64dbg is not yet running and you need to start a debug session. "
                "Waits for the AI Agent plugin to become connectable after launch.",
                {
                    "target_exe": {
                        "type": "string",
                        "description": "Path to the target executable to load in x64dbg. Optional.",
                    },
                    "wait_seconds": {
                        "type": "number",
                        "default": 3.0,
                        "description": "Seconds to wait after launch before attempting connection (default 3).",
                    },
                },
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "x64dbg_status",
                "Get x64dbg connection status, process state, and bridge info.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "x64dbg_connect",
                "Attempt to (re)connect to a running x64dbg instance. "
                "USE WHEN: x64dbg is already running but Claude is not connected.",
                {},
                output_schema=_STANDARD_OUTPUT,
            ),
            _tool(
                "x64dbg_eval_expression",
                "Evaluate a debugger expression and return the numeric result. "
                "Sends the eval_expression command directly to the x64dbg plugin for extended expression support. "
                "Resolves register names, API addresses, arithmetic, pointer dereferences. "
                "USE WHEN: you need to resolve a symbol address or compute a pointer value. "
                "Examples: 'kernel32.VirtualAlloc', 'rax+8', '[rsp+0x28]', 'ntdll.NtQueryInformationProcess'.",
                {
                    "expression": {
                        "type": "string",
                        "description": "Expression to evaluate in x64dbg expression format. "
                                       "Examples: 'IsDebuggerPresent', 'rip+0x10', 'kernel32.GetProcAddress', '[rsp]'.",
                    },
                },
                required=["expression"],
                output_schema=_STANDARD_OUTPUT,
            ),
        ]

    # ------------------------------------------------------------------
    # Resource definitions
    # ------------------------------------------------------------------
    def _get_resources(self) -> list[dict]:
        return [
            {
                "uri": "debugger://registers",
                "name": "CPU Registers",
                "description": "Current CPU register values (live snapshot)",
                "mimeType": "application/json",
            },
            {
                "uri": "debugger://memory-map",
                "name": "Memory Map",
                "description": "Process virtual memory layout with protection flags",
                "mimeType": "application/json",
            },
            {
                "uri": "debugger://modules",
                "name": "Loaded Modules",
                "description": "List of loaded DLLs and their base addresses",
                "mimeType": "application/json",
            },
            {
                "uri": "debugger://breakpoints",
                "name": "Breakpoints",
                "description": "Active breakpoints set by the agent",
                "mimeType": "application/json",
            },
            {
                "uri": "debugger://context",
                "name": "Agent Context",
                "description": "Current debugging context (findings, patterns, functions)",
                "mimeType": "application/json",
            },
            {
                "uri": "debugger://patterns",
                "name": "Known Patterns",
                "description": "Database of known binary patterns (packers, anti-debug, crypto)",
                "mimeType": "application/json",
            },
        ]

    # ------------------------------------------------------------------
    # Prompt templates
    # ------------------------------------------------------------------
    def _get_prompts(self) -> list[dict]:
        return [
            {
                "name": "analyze_binary",
                "description": "Comprehensive binary analysis workflow",
                "arguments": [
                    {"name": "focus", "description": "Focus area: general, unpacking, w, crypto", "required": False},
                ],
            },
            {
                "name": "trace_execution",
                "description": "Trace execution flow and document findings",
                "arguments": [
                    {"name": "from_address", "description": "Start address (hex)", "required": False},
                    {"name": "steps", "description": "Number of steps to trace", "required": False},
                ],
            },
            {
                "name": "find_vulnerabilities",
                "description": "Search for potential security vulnerabilities",
                "arguments": [],
            },
        ]

    # ------------------------------------------------------------------
    # Message handling
    # ------------------------------------------------------------------
    async def handle_message(self, message: dict) -> dict:
        """Handle incoming JSON-RPC message."""
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {})

        handler = {
            "initialize": self._handle_initialize,
            "initialized": self._handle_initialized,
            "notifications/initialized": self._handle_initialized,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "resources/list": self._handle_resources_list,
            "resources/read": self._handle_resources_read,
            "prompts/list": self._handle_prompts_list,
            "prompts/get": self._handle_prompts_get,
            "ping": self._handle_ping,
        }.get(method)

        if handler:
            result = await handler(params)
            if msg_id is not None:
                return {"jsonrpc": "2.0", "id": msg_id, "result": result}
            return None
        else:
            if msg_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                }
            return None

    async def _handle_initialize(self, params: dict) -> dict:
        return {
            "protocolVersion": self.PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
            },
        }

    async def _handle_initialized(self, params: dict):
        return None

    async def _handle_ping(self, params: dict) -> dict:
        return {}

    async def _handle_tools_list(self, params: dict) -> dict:
        return {"tools": self._get_tools()}

    async def _handle_tools_call(self, params: dict) -> dict:
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {}) or {}

        try:
            result = await self._dispatch_tool(tool_name, arguments)
            text = json.dumps(result, indent=2, ensure_ascii=False)
            response = {
                "content": [{"type": "text", "text": text}],
                "structuredContent": result,
            }
            if not result.get("success", True):
                response["isError"] = True
            return response
        except Exception as e:
            err = self._error("INTERNAL_ERROR", f"Tool dispatch failed: {e}",
                              "Check server logs for full traceback.")
            return {
                "content": [{"type": "text", "text": json.dumps(err, indent=2)}],
                "structuredContent": err,
                "isError": True,
            }

    async def _handle_resources_list(self, params: dict) -> dict:
        return {"resources": self._get_resources()}

    async def _handle_resources_read(self, params: dict) -> dict:
        uri = params.get("uri", "")
        content = await self._read_resource(uri)
        return {
            "contents": [
                {"uri": uri, "mimeType": "application/json", "text": json.dumps(content, indent=2)},
            ],
        }

    async def _handle_prompts_list(self, params: dict) -> dict:
        return {"prompts": self._get_prompts()}

    async def _handle_prompts_get(self, params: dict) -> dict:
        name = params.get("name", "")
        arguments = params.get("arguments", {})
        messages = self._get_prompt_messages(name, arguments)
        return {"messages": messages}

    # ------------------------------------------------------------------
    # Tool dispatch — maps consolidated MCP tools to underlying skills
    # ------------------------------------------------------------------
    async def _dispatch_tool(self, name: str, args: dict) -> dict:
        """Route a tool call to the right skill(s) and return structured JSON."""

        # Agent-level meta-tools
        if name == "agent_analyze":
            goal = args.get("goal", "")
            if not goal or len(goal) < 5:
                return self._error(
                    "INVALID_ARGUMENT",
                    "Goal is required and must be at least 5 characters",
                    "Provide a specific goal like 'Find the unpacking loop' or 'Identify anti-debug checks'",
                )
            max_steps = int(_arg(args, "max_steps", 15))
            saved_max = self.agent.MAX_REACT_STEPS
            try:
                self.agent.MAX_REACT_STEPS = max_steps
                thoughts = await self.agent.run(goal)
                return {
                    "success": True,
                    "summary": f"Analysis complete: {len(thoughts)} steps for goal {goal!r}",
                    "data": {
                        "goal": goal,
                        "steps": [
                            {
                                "step": t.step,
                                "observation": t.observation,
                                "reasoning": t.reasoning,
                                "action": t.action if t.action and not t.action.startswith("__") else None,
                                "result": t.result[:1000] if t.result else None,
                            }
                            for t in thoughts
                        ],
                    },
                    "details": self._format_thoughts(thoughts),
                }
            finally:
                self.agent.MAX_REACT_STEPS = saved_max

        if name == "agent_get_context":
            ctx = self.agent.context
            return {
                "success": True,
                "summary": f"Context: target={ctx.target_process or 'none'}, "
                           f"{len(ctx.known_functions)} functions, "
                           f"{len(ctx.breakpoints)} breakpoints, "
                           f"{len(ctx.patterns_found)} patterns",
                "data": {
                    "target": ctx.target_process,
                    "pid": ctx.target_pid,
                    "base_address": f"0x{ctx.base_address:X}" if ctx.base_address else None,
                    "current_rip": f"0x{ctx.current_rip:X}" if ctx.current_rip else None,
                    "breakpoints": ctx.breakpoints,
                    "known_functions": {f"0x{k:X}": v for k, v in ctx.known_functions.items()},
                    "patterns_found": ctx.patterns_found,
                    "goal": ctx.goal,
                },
            }

        if name == "memory_recall":
            query = args.get("query", "")
            if not query:
                return self._error("INVALID_ARGUMENT", "Missing 'query' argument",
                                   "Provide a search query like 'unpacking' or 'crypto'")
            insights = self.agent.memory.recall_relevant(query)
            return {
                "success": True,
                "summary": f"Found {len(insights)} relevant insights for {query!r}",
                "data": {"query": query, "insights": insights},
            }

        if name == "list_known_patterns":
            category = _arg(args, "category", "all")
            if category in ("all", "", None):
                patterns = self.agent.memory.get_all_patterns()
            else:
                patterns = self.agent.memory.get_patterns_by_category(category)
            return {
                "success": True,
                "summary": f"{len(patterns)} known patterns" + (f" in '{category}'" if category not in ("all", "", None) else ""),
                "data": [
                    {"name": p.name, "category": p.category, "pattern": p.pattern, "description": p.description}
                    for p in patterns
                ],
            }

        # Execution control
        if name == "execution_control":
            action = args.get("action")
            if action == "run":
                return await self._run_skill("run", {})
            if action == "pause":
                return await self._run_skill("pause", {})
            if action == "step_into":
                return await self._run_skill("step_into", {})
            if action == "step_over":
                return await self._run_skill("step_over", {})
            if action == "step_n":
                return await self._run_skill("step_n", {
                    "count": _arg(args, "count", 10),
                    "type": _arg(args, "step_type", "over"),
                })
            if action == "run_to":
                if not args.get("address"):
                    return self._error("MISSING_ARGUMENT",
                                       "'run_to' requires 'address'",
                                       "Example: {\"action\": \"run_to\", \"address\": \"0x401234\"}")
                return await self._run_skill("run_to", {"address": args.get("address")})
            return self._error("INVALID_ACTION", f"Unknown execution action: {action}",
                               "Use one of: run, pause, step_into, step_over, step_n, run_to")

        if name == "get_registers":
            return await self._run_skill("get_registers", {})
        if name == "set_register":
            return await self._run_skill("set_register", {
                "register": args.get("register"),
                "value": args.get("value"),
            })

        # Disassembly & analysis
        if name == "disassemble":
            return await self._run_skill("disassemble", {
                "address": args.get("address"),
                "count": _arg(args, "count", 30),
            })
        if name == "analyze_function":
            return await self._run_skill("analyze_function", {"address": args.get("address")})
        if name == "get_xrefs":
            return await self._run_skill("get_xrefs", {
                "address": args.get("address"),
                "direction": _arg(args, "direction", "to"),
            })
        if name == "evaluate_expression":
            return await self._run_skill("evaluate", {"expression": args.get("expression")})
        if name == "get_call_stack":
            return await self._run_skill("get_call_stack", {})

        # Process / modules
        if name == "process_info":
            return await self._run_skill("get_process_info", {})
        if name == "list_modules":
            return await self._run_skill("get_modules", {})
        if name == "list_imports":
            return await self._run_skill("get_imports", {"module": args.get("module")})
        if name == "list_exports":
            return await self._run_skill("get_exports", {"module": args.get("module")})
        if name == "get_threads":
            return await self._run_skill("get_threads", {})
        if name == "get_peb":
            return await self._run_skill("get_peb_info", {})
        if name == "get_handles":
            return await self._run_skill("get_handles", {})

        # Memory ops
        if name == "memory_map":
            return await self._run_skill("get_memory_map", {})
        if name == "read_memory":
            return await self._run_skill("read_memory", {
                "address": args.get("address"),
                "size": _arg(args, "size", 256),
            })
        if name == "write_memory":
            return await self._run_skill("write_memory", {
                "address": args.get("address"),
                "data": args.get("data"),
            })
        if name == "read_string":
            return await self._run_skill("read_string", {
                "address": args.get("address"),
                "max_len": _arg(args, "max_len", 256),
            })
        if name == "search_pattern":
            return await self._run_skill("search_pattern", {
                "pattern": args.get("pattern"),
                "module": args.get("module"),
            })
        if name == "search_strings":
            return await self._run_skill("search_strings", {"min_length": _arg(args, "min_length", 4)})
        if name == "allocate_memory":
            return await self._run_skill("allocate_memory", {
                "size": _arg(args, "size", 4096),
                "protection": _arg(args, "protection", 0x04),
            })

        # Breakpoints
        if name == "breakpoint":
            return await self._dispatch_breakpoint(args)
        if name == "breakpoint_on_api_group":
            return await self._run_skill("bp_on_api_group", {"group": args.get("group")})

        # Bossix
        if name == "bossix_scan":
            return await self._run_skill("scan_bossix", {})
        if name == "bossix_hide":
            return await self._run_skill("hide_bossix", {})
        if name == "bossix_patch":
            return await self._run_skill("patch_bossix", {
                "address": args.get("address"),
                "technique": args.get("technique", ""),
            })

        # Advanced
        if name == "execute_command":
            return await self._run_skill("execute_command", {"command": args.get("command")})
        if name == "dump_module":
            return await self._run_skill("dump_module", {
                "module": args.get("module"),
                "output": args.get("output", ""),
            })
        if name == "run_script":
            return await self._run_skill("run_script", {"script": args.get("script")})

        if name == "x64dbg_launch":
            target = _arg(args, "target_exe")
            wait  = float(_arg(args, "wait_seconds", 3.0))
            try:
                connected = await self.agent.bridge.launch_x64dbg(
                    target_exe=target, wait_seconds=wait
                )
                return {
                    "success": connected,
                    "summary": (
                        f"x64dbg launched and connected (target: {target or 'none'})"
                        if connected else
                        f"x64dbg launched but not yet connected — try x64dbg_connect"
                    ),
                    "data": {
                        "connected": connected,
                        "target": target,
                        "x64dbg_running": self.agent.bridge.is_x64dbg_running(),
                    },
                }
            except FileNotFoundError as e:
                return self._error("NOT_FOUND", str(e), "Set X64DBG_PATH environment variable")
            except Exception as e:
                return self._error("LAUNCH_ERROR", str(e), "Check x64dbg path and plugin installation")

        if name == "x64dbg_status":
            bridge = self.agent.bridge
            return {
                "success": True,
                "summary": f"x64dbg {'connected' if bridge.connected else 'disconnected'} "
                           f"| protocol: {bridge.protocol.name} "
                           f"| x64dbg process: {'running' if bridge.is_x64dbg_running() else 'not launched'}",
                "data": {
                    "connected": bridge.connected,
                    "protocol": bridge.protocol.name,
                    "pipe_name": bridge.pipe_name,
                    "http_url": bridge.http_url,
                    "x64dbg_path": bridge.x64dbg_path,
                    "x64dbg_process_running": bridge.is_x64dbg_running(),
                    "connection_state": bridge.state.name,
                    "agent_state": self.agent.state.name,
                    "context_target": self.agent.context.target_process,
                    "breakpoints": len(self.agent.context.breakpoints),
                },
            }

        if name == "x64dbg_connect":
            try:
                connected = await self.agent.bridge.connect()
                return {
                    "success": connected,
                    "summary": "Connected to x64dbg" if connected else
                               "Could not connect — is x64dbg running with AI Agent plugin loaded?",
                    "data": {"connected": connected, "protocol": self.agent.bridge.protocol.name},
                    "suggested_next_tools": ["process_info", "get_registers"] if connected else ["x64dbg_launch"],
                }
            except Exception as e:
                return self._error("CONNECT_ERROR", str(e),
                                   "Start x64dbg, load the AI Agent plugin, then retry")

        if name == "x64dbg_eval_expression":
            expr = args.get("expression", "")
            if not expr:
                return self._error(
                    "MISSING_ARGUMENT",
                    "Missing required 'expression' argument",
                    "Example: {\"expression\": \"kernel32.VirtualAlloc\"}",
                )
            result = await self.agent.bridge.eval_expression(expr)
            if "error" in result:
                return self._error(
                    "EVAL_ERROR",
                    result["error"],
                    "Check expression syntax; use x64dbg expression format (e.g. 'rax+8', '[rsp]').",
                )
            value = result.get("value")
            hex_value = hex(value) if isinstance(value, int) else None
            return {
                "success": True,
                "summary": f"Expression '{expr}' = {hex_value or value}",
                "data": {
                    "expression": expr,
                    "value": value,
                    "hex": hex_value,
                },
            }

        return self._error(
            "UNKNOWN_TOOL",
            f"Unknown tool: {name}",
            "Use tools/list to discover available tools",
        )

    async def _dispatch_breakpoint(self, args: dict) -> dict:
        """Route breakpoint actions to the right skill."""
        action = args.get("action")

        if action == "list":
            bps = self.agent.context.breakpoints
            return {
                "success": True,
                "summary": f"{len(bps)} active breakpoints",
                "data": bps,
            }

        if action == "set":
            if not args.get("address") and not args.get("api"):
                return self._error(
                    "MISSING_ARGUMENT",
                    "'set' requires either 'address' or 'api'",
                    "Examples: {\"action\":\"set\",\"address\":\"0x401000\"} or "
                    "{\"action\":\"set\",\"api\":\"IsDebuggerPresent\"}",
                )
            return await self._run_skill("set_breakpoint", {
                "address": args.get("address"),
                "api": args.get("api"),
            })
        if action == "set_hw":
            if not args.get("address"):
                return self._error("MISSING_ARGUMENT", "'set_hw' requires 'address'",
                                   "Example: {\"action\":\"set_hw\",\"address\":\"0x401000\",\"hw_condition\":\"execute\"}")
            return await self._run_skill("set_hw_breakpoint", {
                "address": args.get("address"),
                "condition": _arg(args, "hw_condition", "execute"),
                "size": _arg(args, "size", 1),
            })
        if action == "set_mem":
            if not args.get("address"):
                return self._error("MISSING_ARGUMENT", "'set_mem' requires 'address'",
                                   "Example: {\"action\":\"set_mem\",\"address\":\"0x401000\",\"mem_access\":\"write\"}")
            return await self._run_skill("set_mem_breakpoint", {
                "address": args.get("address"),
                "size": _arg(args, "size", 4),
                "access_type": _arg(args, "mem_access", "write"),
            })
        if action == "set_conditional":
            if not args.get("address"):
                return self._error("MISSING_ARGUMENT", "'set_conditional' requires 'address'",
                                   "Example: {\"action\":\"set_conditional\",\"address\":\"0x401000\",\"condition\":\"rcx == 0x1000\"}")
            return await self._run_skill("set_conditional_bp", {
                "address": args.get("address"),
                "condition": _arg(args, "condition", ""),
                "log": _arg(args, "log", ""),
            })
        if action == "delete":
            if not args.get("address"):
                return self._error("MISSING_ARGUMENT", "'delete' requires 'address'",
                                   "Example: {\"action\":\"delete\",\"address\":\"0x401000\"}")
            return await self._run_skill("delete_breakpoint", {"address": args.get("address")})

        return self._error(
            "INVALID_ACTION",
            f"Unknown breakpoint action: {action}",
            "Use one of: set, set_hw, set_mem, set_conditional, delete",
        )

    # Skill names → MCP tool names. Skills use internal names in their
    # `suggestions` lists; models need the MCP-facing tool name instead.
    _SKILL_TO_TOOL = {
        "run": "execution_control",
        "pause": "execution_control",
        "step_into": "execution_control",
        "step_over": "execution_control",
        "step_n": "execution_control",
        "run_to": "execution_control",
        "get_registers": "get_registers",
        "set_register": "set_register",
        "execute_command": "execute_command",
        "disassemble": "disassemble",
        "analyze_function": "analyze_function",
        "get_xrefs": "get_xrefs",
        "get_modules": "list_modules",
        "get_imports": "list_imports",
        "get_exports": "list_exports",
        "get_call_stack": "get_call_stack",
        "evaluate": "evaluate_expression",
        "get_process_info": "process_info",
        "get_threads": "get_threads",
        "get_peb_info": "get_peb",
        "get_handles": "get_handles",
        "read_memory": "read_memory",
        "write_memory": "write_memory",
        "read_string": "read_string",
        "get_memory_map": "memory_map",
        "search_pattern": "search_pattern",
        "search_strings": "search_strings",
        "allocate_memory": "allocate_memory",
        "set_breakpoint": "breakpoint",
        "set_hw_breakpoint": "breakpoint",
        "set_mem_breakpoint": "breakpoint",
        "set_conditional_bp": "breakpoint",
        "delete_breakpoint": "breakpoint",
        "bp_on_api_group": "breakpoint_on_api_group",
        "scan_bossix": "bossix_scan",
        "hide_bossix": "bossix_hide",
        "patch_bossix": "bossix_patch",
        "dump_module": "dump_module",
        "run_script": "run_script",
    }

    def _translate_suggestions(self, suggestions: list) -> list:
        """Map internal skill names in suggestions to MCP tool names."""
        translated = []
        seen = set()
        for s in suggestions:
            tool_name = self._SKILL_TO_TOOL.get(s, s)
            if tool_name not in seen:
                seen.add(tool_name)
                translated.append(tool_name)
        return translated

    async def _run_skill(self, skill_name: str, args: dict) -> dict:
        """Execute a skill and return structured JSON."""
        skill = self.agent.skills.get(skill_name)
        if not skill:
            return self._error(
                "SKILL_NOT_FOUND",
                f"Internal: skill '{skill_name}' not registered",
                "This is an internal routing bug; please report.",
            )
        try:
            result = await skill.execute(self.agent.bridge, self.agent.context, args)
            output = result.to_json()
            if "suggested_next_tools" in output:
                output["suggested_next_tools"] = self._translate_suggestions(
                    output["suggested_next_tools"]
                )
            return output
        except Exception as e:
            return self._error(
                "SKILL_EXCEPTION",
                f"Skill '{skill_name}' raised: {e}",
                "Check that the debugger is connected and the process is paused.",
            )

    @staticmethod
    def _error(code: str, message: str, hint: str = "") -> dict:
        return {
            "success": False,
            "summary": message,
            "error": {"code": code, "message": message, "hint": hint},
        }

    def _format_thoughts(self, thoughts) -> str:
        """Format ReAct thoughts into readable output."""
        lines = ["Agent Analysis Report", "=" * 40]
        for t in thoughts:
            lines.append(f"\nStep {t.step}:")
            lines.append(f"  Observation: {t.observation}")
            lines.append(f"  Reasoning: {t.reasoning}")
            if t.action and not t.action.startswith("__"):
                lines.append(f"  Action: {t.action}")
            if t.result:
                lines.append(f"  Result: {t.result[:500]}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Resource reading
    # ------------------------------------------------------------------
    async def _read_resource(self, uri: str) -> Any:
        if uri == "debugger://registers":
            return await self.agent.bridge.get_registers() or {}
        elif uri == "debugger://memory-map":
            return await self.agent.bridge.get_memory_map()
        elif uri == "debugger://modules":
            return await self.agent.bridge.get_modules()
        elif uri == "debugger://breakpoints":
            return self.agent.context.breakpoints
        elif uri == "debugger://context":
            ctx = self.agent.context
            return {
                "target": ctx.target_process,
                "known_functions": len(ctx.known_functions),
                "patterns_found": len(ctx.patterns_found),
                "breakpoints": len(ctx.breakpoints),
            }
        elif uri == "debugger://patterns":
            return [
                {"name": p.name, "pattern": p.pattern, "category": p.category, "description": p.description}
                for p in self.agent.memory.get_all_patterns()
            ]
        return {}

    # ------------------------------------------------------------------
    # Prompt templates
    # ------------------------------------------------------------------
    def _get_prompt_messages(self, name: str, arguments: dict) -> list[dict]:
        if name == "analyze_binary":
            focus = arguments.get("focus", "general")
            return [{"role": "user", "content": {
                "type": "text",
                "text": f"""Analyze the binary currently loaded in x64dbg. Focus: {focus}.

Steps:
1. Use process_info to identify the target
2. Use list_imports to understand API usage
3. Use memory_map to find suspicious regions (RWX, large allocations)
4. Use bossix_scan to check for bossix
5. Use disassemble at the entry point to understand initialization
6. Report findings with addresses and recommendations

Be thorough. For each finding, explain WHY it matters for reverse engineering."""
            }}]

        elif name == "trace_execution":
            addr = arguments.get("from_address", "current RIP")
            steps = arguments.get("steps", "20")
            return [{"role": "user", "content": {
                "type": "text",
                "text": f"""Trace execution starting from {addr} for {steps} steps.

For each significant instruction:
- Note API calls and their arguments
- Track memory allocations and protection changes
- Identify control flow decisions (conditional jumps)
- Flag any anti-debug or evasion techniques
- Document string references

Use execution_control with action='step_n' and the appropriate count, then analyze the trace."""
            }}]

        elif name == "find_vulnerabilities":
            return [{"role": "user", "content": {
                "type": "text",
                "text": """Scan the binary for potential security vulnerabilities:

1. Check imports for dangerous functions (strcpy, sprintf, gets, etc.)
2. Look for format string vulnerabilities
3. Check for integer overflow patterns
4. Identify unsafe memory operations
5. Look for hardcoded credentials or keys
6. Check for insecure crypto usage

Use search_strings to find interesting strings, then analyze surrounding code."""
            }}]

        return []

    # ------------------------------------------------------------------
    # stdio transport
    # ------------------------------------------------------------------
    async def run_stdio(self):
        """Run MCP server on stdin/stdout (stdio transport)."""
        self._running = True
        loop = asyncio.get_running_loop()

        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        stdout = sys.stdout.buffer

        while self._running:
            try:
                line = await reader.readline()
                if not line:
                    break

                line_str = line.decode('utf-8').strip()
                if not line_str:
                    continue

                message = json.loads(line_str)
                response = await self.handle_message(message)

                if response:
                    output = json.dumps(response).encode('utf-8') + b"\n"
                    stdout.write(output)
                    stdout.flush()

            except json.JSONDecodeError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)},
                }
                stdout.write(json.dumps(error_response).encode('utf-8') + b"\n")
                stdout.flush()


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    """Start MCP server."""
    from .bridge import X64DbgBridge
    from .core import DebuggerAgent

    bridge = X64DbgBridge()
    agent = DebuggerAgent(bridge)
    server = MCPServer(agent)

    asyncio.run(server.run_stdio())


if __name__ == "__main__":
    main()
