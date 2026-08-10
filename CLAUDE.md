# MCO — Multi-debugger Controller Orchestrator

MCP server platform that connects WinDbg, IDA Pro 9.x, and x64dbg to Claude AI for AI-assisted reverse engineering and Windows security research.

**Owner:** Windows security researcher (heap exploitation, anti-debug).
**Language policy:** Code and docs in English; user communicates in Russian (informal).

---

## Repository layout

```
C:\Users\dange\mcp\mco\
├── windbg_mcp.py            # WinDbg via cdb.exe subprocess. 70+ tools. PRODUCTION.
├── ida_mcp.py               # IDA Pro 9.x via HTTP REST (localhost:2022). 32+ tools.
├── ida_server_plugin.py     # Paste into IDA Python console to start HTTP server.
├── agent/                   # x64dbg MCP via named pipe
│   ├── __main__.py          # Entry: python -m agent --mcp
│   ├── core.py              # Shared debugging context (bridge, skills, state)
│   ├── bridge.py            # Named-pipe IPC to x64dbg C++ plugin
│   ├── mcp_server.py        # MCP server + 35+ tool definitions
│   └── plugins/
│       ├── x64dbg_plugin.cpp   # C++ plugin — compile with build_plugin.bat
│       └── build_plugin.bat    # MSVC build (produces mco_agent.dp64)
├── mco_orchestrator.py      # Cross-debugger meta-tools. 7 compound workflows.
├── mco_sessions.py          # SQLite session recorder/replayer. 13 tools.
├── mcp_config_example.json  # All MCP server configs with env vars
├── pyproject.toml           # Python package (x64dbg-mcp-agent)
├── sessions.db              # SQLite DB (auto-created by mco_sessions.py)
├── site/index.html          # Startup landing page
└── .windbg_mcp_breakpoints/ # Saved breakpoint sets (cmd files)
```

---

## MCP servers — quick reference

| Server name    | File                   | Provides                                    | Tool count |
|----------------|------------------------|---------------------------------------------|------------|
| `windbg`       | `windbg_mcp.py`        | Crash dumps, heap, shadow stack, kernel     | 70+        |
| `ida`          | `ida_mcp.py`           | Static analysis, decompile, rename, patches | 32+        |
| `x64dbg`       | `agent/__main__.py`    | Dynamic analysis, anti-debug bypass        | 35+        |
| `mco`          | `mco_orchestrator.py`  | Cross-debugger compound workflows           | 7          |
| `mco-sessions` | `mco_sessions.py`      | Session recording, FTS search, export      | 13         |

---

## Adding servers to Claude Code

```powershell
# Run from any directory
claude mcp add windbg     -- python "C:\Users\dange\mcp\mco\windbg_mcp.py"
claude mcp add ida        -- python "C:\Users\dange\mcp\mco\ida_mcp.py"
claude mcp add mco        -- python "C:\Users\dange\mcp\mco\mco_orchestrator.py"
claude mcp add mco-sessions -- python "C:\Users\dange\mcp\mco\mco_sessions.py"

# x64dbg: cwd MUST be the mco directory
claude mcp add x64dbg -- python -m agent --mcp
# (set cwd to C:\Users\dange\mcp\mco in your MCP client config)
```

Use `mcp_config_example.json` as a reference for full JSON config including env vars.

---

## Pre-flight: what needs to be running

### WinDbg server
- Needs `cdb.exe` at the path set in `CDB_PATH` / `WINDBG_MCP_CDB`
- Default: `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`
- No process needed pre-launch — tools open dumps or attach on demand.

### IDA server
- IDA Pro 9.x must be open with a binary loaded.
- Then in IDA's Python console (Alt+F7 or Python tab):
  ```python
  exec(open(r'C:\Users\dange\mcp\mco\ida_server_plugin.py').read())
  ```
- IDA 9.x may auto-start the HTTP server on port 2022; if not, the plugin starts it.
- The client auto-discovers the right endpoint from 6 candidates (`/api/v1/py`, `/api/python`, `/python`, `/exec`, `/api/1/exec`, `/api/v1/python`).

### x64dbg server
- x64dbg must be running with the `mco_agent.dp64` plugin loaded.
- Build the plugin: `cd agent\plugins && build_plugin.bat`
- Copy `mco_agent.dp64` to x64dbg's plugins folder, restart x64dbg.
- The plugin exposes a named pipe at `\\.\pipe\x64dbg_ai_agent`.
- Rebuild required if `bridge.py` protocol changes (magic header `X64A` + 4-byte len + 8 padding bytes).

### Orchestrator / Sessions
- Work standalone — no debugger required to add the servers.
- `mco` makes direct connections to cdb.exe, IDA HTTP, and x64dbg pipe.
- `mco-sessions` only needs SQLite (`sessions.db` in project root).

---

## Environment variables

### WinDbg (`windbg_mcp.py`)
| Variable            | Default                                                              | Purpose                        |
|---------------------|----------------------------------------------------------------------|--------------------------------|
| `WINDBG_MCP_CDB`    | `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`     | Path to cdb.exe                |
| `CDB_PATH`          | same default                                                         | Alias used by orchestrator     |

### IDA (`ida_mcp.py`)
| Variable         | Default       | Purpose                              |
|------------------|---------------|--------------------------------------|
| `IDA_MCP_HOST`   | `localhost`   | IDA HTTP server host                 |
| `IDA_MCP_PORT`   | `2022`        | IDA HTTP server port                 |
| `IDA_MCP_TIMEOUT`| `30`          | Request timeout in seconds           |
| `IDA_MCP_TOKEN`  | _(empty)_     | Bearer token if IDA requires auth    |
| `IDA_PATH`       | `C:\Program Files\IDA Professional 9.2` | IDA install dir    |

### x64dbg (`agent/`)
| Variable       | Default                          | Purpose                             |
|----------------|----------------------------------|-------------------------------------|
| `X64DBG_PATH`  | _(must be set)_                  | Path to x64dbg.exe for auto-launch  |
| `X64DBG_PIPE`  | `\\.\pipe\x64dbg_ai_agent`       | Named pipe (override if custom)     |

### Orchestrator (`mco_orchestrator.py`)
| Variable     | Default                         | Purpose                       |
|--------------|---------------------------------|-------------------------------|
| `CDB_PATH`   | default cdb.exe path            | cdb.exe for orchestrator      |
| `IDA_HOST`   | `localhost`                     | IDA HTTP host                 |
| `IDA_PORT`   | `2022`                          | IDA HTTP port                 |
| `X64DBG_PIPE`| `\\.\pipe\x64dbg_ai_agent`      | x64dbg named pipe             |

### Sessions (`mco_sessions.py`)
| Variable          | Default                                  | Purpose          |
|-------------------|------------------------------------------|------------------|
| `MCO_SESSIONS_DB` | `<project_dir>\sessions.db`             | SQLite DB path   |

---

## Key tools per server

### WinDbg (`windbg` server) — 70+ tools

| Tool | Description |
|------|-------------|
| `windbg_open_dump` | Open a .dmp crash dump in cdb.exe |
| `windbg_analyze_crash` | Run `!analyze -v` — full automated crash analysis |
| `windbg_call_stack` | Get call stack (supports `!wke`, thread switching) |
| `windbg_heap_block_info` | Inspect a heap block: size, flags, neighbors |
| `windbg_heap_neighbors` | Show adjacent heap chunks (UAF/overflow investigation) |
| `windbg_shadow_stack` | Dump CET shadow stack (Intel CET / Win11 HVCI) |
| `windbg_shadow_stack_compare` | Diff shadow stack vs regular call stack (ROP detection) |
| `windbg_crash_triage` | Quick triage: fault type, module, exploitability estimate |
| `windbg_heap_spray_check` | Detect heap spray patterns in process heap |
| `windbg_find_vtable_owner` | Identify which class owns a vtable pointer |
| `windbg_peb` / `windbg_teb` | Dump PEB/TEB structures |
| `windbg_exception_chain` | Walk SEH chain |
| `windbg_asan_parse` | Parse ASAN output into structured findings |
| `windbg_watch_memory` | Set memory access watchpoint |
| `windbg_run_command` | Raw cdb.exe command pass-through |
| `windbg_save_breakpoints` / `windbg_load_breakpoints` | Persist BP sets to `.windbg_mcp_breakpoints/` |

**Important:** Do NOT lightly edit `windbg_mcp.py` — it is 3089 lines of production-hardened code with complex async cdb.exe I/O management.

### IDA Pro (`ida` server) — 32+ tools

| Tool | Description |
|------|-------------|
| `ida_decompile` | Hex-Rays decompile function at address → pseudocode |
| `ida_disassemble` | Disassemble N instructions at address |
| `ida_functions` | List all functions (filterable, paginated) |
| `ida_imports` | Import table grouped by module |
| `ida_strings` | All strings in binary (min_len, limit) |
| `ida_xrefs_to` / `ida_xrefs_from` | Cross-references to/from an address |
| `ida_rename` | Rename a function or label |
| `ida_scan_bossix` | Static scan for 14 bossix API call sites |
| `ida_find_crypto` | Detect crypto constants (AES S-box, RC4, etc.) |
| `ida_patch_bytes` | Patch bytes in IDB (e.g., NOP a check) |
| `ida_call_tree` | Recursive call tree to specified depth |
| `ida_diff_functions` | Instruction-level diff between two functions |
| `ida_find_string_refs` | Find all XREFs to a string matching a pattern |
| `ida_run_script` | Execute arbitrary IDAPython in IDA's context |
| `ida_get_pseudocode_all_functions` | Bulk decompile up to N functions |
| `ida_apply_signature` | Apply a FLIRT `.sig` file |
| `ida_struct` | Look up an IDB struct definition |

### x64dbg (`x64dbg` server) — 35+ tools

**Session context:**
| Tool | Description |
|------|-------------|
| `agent_get_context` | Current session state: RIP, breakpoints, discovered functions |

**Execution & registers:**
| Tool | Description |
|------|-------------|
| `execution_control` | `run` / `pause` / `step_into` / `step_over` / `step_n` / `run_to` |
| `get_registers` | Read all GPRs + RFLAGS |
| `set_register` | Write a register (bypass IsDebuggerPresent: set RAX=0) |
| `get_call_stack` | Thread call stack with module!function |

**Analysis:**
| Tool | Description |
|------|-------------|
| `disassemble` | Disassemble with auto-categorized CALLs and JMPs |
| `analyze_function` | Deep: disasm + xrefs + API calls + crypto indicators |
| `get_xrefs` | Cross-references to/from an address |
| `evaluate_expression` | x64dbg expression: `kernel32.VirtualAlloc`, `[rsp]`, `rip+0x10` |

**Process / memory:**
| Tool | Description |
|------|-------------|
| `process_info` | Main module, base, entry point, threads, PEB summary |
| `memory_map` | Virtual memory map — auto-flags RWX regions |
| `read_memory` / `write_memory` | Hex+ASCII read; hex-string write |
| `search_pattern` | Byte search with `??` wildcards |
| `search_strings` | All strings, auto-categorized: URLs / paths / registry / APIs |
| `get_peb` | Full PEB dump with anti-debug flag analysis |
| `allocate_memory` | Allocate in target (PAGE_READWRITE or PAGE_EXECUTE_READWRITE) |

**Breakpoints:**
| Tool | Description |
|------|-------------|
| `breakpoint` | Unified: `set` / `set_hw` / `set_mem` / `set_conditional` / `delete` / `list` |
| `breakpoint_on_api_group` | Set BPs on entire category: `memory` / `network` / `inject` / `crypto` / `bossix` / etc. |

**Bossix:**
| Tool | Description |
|------|-------------|
| `bossix_scan` | Full scan: PEB flags + API imports + RDTSC + byte patterns |
| `bossix_hide` | PEB patch: zero BeingDebugged, clear NtGlobalFlag, x64dbg hide |
| `bossix_patch` | Auto-patch instruction at address (NOP / flip JCC / xor eax,eax) |

**Advanced:**
| Tool | Description |
|------|-------------|
| `dump_module` | Dump unpacked module to disk |
| `run_script` | Multi-line x64dbg script, runs atomically |
| `execute_command` | Raw x64dbg command escape hatch |
| `x64dbg_launch` | Launch x64dbg.exe (waits for plugin pipe) |

### MCO Orchestrator (`mco` server) — 7 tools

| Tool | Description |
|------|-------------|
| `mco_status` | Check which debuggers are live right now |
| `mco_crash_to_source` | Pipeline: open dump → `!analyze -v` → extract RIP → IDA decompile |
| `mco_pivot_to_ida` | Take any hex address → IDA: function name, pseudocode, callers, callees |
| `mco_bossix_report` | Combined: IDA static scan + x64dbg PEB check |
| `` | Threat intel: IDA APIs + strings + x64dbg runtime modules/threads |
| `mco_compare_functions` | Binary diff two IDA functions: similarity %, size delta, instruction lists |
| `mco_heap_spray_analysis` | WinDbg `!heap -s` + IDA alloc-site map |

### MCO Sessions (`mco-sessions` server) — 13 tools

| Tool | Description |
|------|-------------|
| `session_start` | Start a named session (sets current active session) |
| `session_end` | Close session, save notes |
| `session_record` | Record any tool call into current session |
| `session_list` | List sessions with duration + tool-call count |
| `session_search` | FTS5 full-text search across ALL tool outputs |
| `session_find_address` | Find sessions that mention a hex address |
| `session_find_function` | Find sessions that mention a function name |
| `session_replay` | Chronological timeline of a session with timestamps |
| `session_summary` | Auto-extract: top tools, key addresses, critical findings |
| `session_export_markdown` | Full Markdown report ready to share |
| `session_stats` | Global: total sessions, total tool calls, top tools, top targets |
| `session_diff` | Compare two sessions: tools only in A/B, call-count diffs, similarity % |
| `session_delete` | Permanently remove session + events |

---

## Common workflows

### 1. Crash dump analysis

```
windbg_open_dump(path="C:\dumps\crash.dmp")
→ windbg_analyze_crash()
→ windbg_call_stack()
→ [note crashing address, e.g. 0x7FF712345678]
→ mco_pivot_to_ida(address="0x7FF712345678")
→ ida_decompile(address="0x7FF712340000")  # function start
```

Or in one shot via orchestrator:
```
mco_crash_to_source(dump_path="C:\dumps\crash.dmp")
```

### 2. Bossix detection and bypass

```
ida_scan_bossix()                         # static: which APIs are called and from where
→ x64dbg_connect() / x64dbg_launch()
→ bossix_scan()                           # dynamic: PEB flags, RDTSC, byte patterns
→ bossix_hide()                           # patch PEB.BeingDebugged + NtGlobalFlag
→ breakpoint(action="set", api="IsDebuggerPresent")
→ execution_control(action="run")
→ get_registers()                             # confirm RIP hit
→ bossix_patch(address="0x401234")        # NOP / flip JCC at the check
→ ida_patch_bytes(address="0x401234", hex_bytes="90 90")  # also patch IDB
```

Or single call:
```
mco_bossix_report()
```

### 3. w static analysis

```
ida_imports()                                 # suspicious APIs
→ ida_find_crypto()                           # crypto constants (AES S-box, RC4, etc.)
→ ida_scan_bossix()
→ ida_strings(min_len=4)                      # IOCs
→ ida_find_string_refs(pattern="cmd.exe")     # find references to cmd.exe
→ ida_decompile(address="<referencing_func>")
→ ida_call_tree(address="<func>", depth=3)
```

Or single call:
```
mco_w_audit()
```

### 4. Heap UAF / overflow investigation

```
windbg_open_dump(path="crash.dmp")
→ windbg_analyze_crash()                      # get faulting address
→ windbg_heap_block_info(address="0xdeadbeef")
→ windbg_heap_neighbors(address="0xdeadbeef", before=0x40, after=0x100)
→ windbg_find_vtable_owner(address="0xdeadbeef")  # if vtable corruption
→ mco_pivot_to_ida(address="0xfaulting_func")
→ ida_xrefs_to(address="0xfree_site")        # find who freed the object
```

Heap spray detection:
```
mco_heap_spray_analysis()
```
or
```
windbg_heap_spray_check()
```

### 5. Binary diffing (patch analysis)

```
# After loading patched binary alongside original in IDA
ida_diff_functions(addr1="0x401000", addr2="0x401000")   # same func, two binaries
# Or via orchestrator:
mco_compare_functions(address_a="0x401000", address_b="0x501000")
```

### 6. Session recording (standard practice)

```
session_start(name="chrome heap uaf analysis", target="chrome.exe", debugger="windbg")
→ [run any analysis tools]
→ session_record(tool_name="windbg_analyze_crash", args={}, result="<output>")
→ session_record(tool_name="ida_decompile", args={"address":"0x..."}, result="<pseudocode>")
→ session_end(notes="UAF at CRenderObject::Destroy, freed at 0x1234, reused at 0x5678")
→ session_export_markdown(session_id=1)
```

Later, search across sessions:
```
session_search(query="use-after-free")
session_find_address(address="0x7ff712345678")
session_find_function(name="NtUserSetWindowPos")
```

### 7. Dynamic unpacking

```
x64dbg_launch(target_exe="C:\w\sample.exe")
→ process_info()
→ breakpoint_on_api_group(group="memory")      # catch VirtualAlloc/VirtualProtect
→ execution_control(action="run")
→ get_registers()                              # when BP hits
→ memory_map()                                 # look for new RWX region
→ execution_control(action="run_to", address="<entry_of_unpacked>")
→ dump_module(module="unpacked.exe")
→ [load dump in IDA for static analysis]
```

---

## x64dbg server modes

| Mode | Command |
|------|---------|
| MCP server (default) | `python -m agent --mcp` |
| Interactive CLI | `python -m agent --cli` |

---

## Quick connectivity tests

```powershell
# WinDbg: check cdb.exe is found
python -c "import subprocess; print(subprocess.run(['C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe', '-version'], capture_output=True, text=True).stdout[:80])"

# IDA: check HTTP server is up
python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:2022/api/v1/py', timeout=3))"

# x64dbg: check named pipe exists
python -c "import os; print('pipe exists' if os.path.exists(r'\\\\.\pipe\x64dbg_ai_agent') else 'plugin not loaded')"

# MCO orchestrator: status of all three
python -c "
import json, subprocess, sys
req = json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'mco_status','arguments':{}}})
r = subprocess.run(['python', r'C:\Users\dange\mcp\mco\mco_orchestrator.py'], input=json.dumps({'jsonrpc':'2.0','id':0,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{}}}) + '\n' + req, capture_output=True, text=True)
print(r.stdout[-800:])
"
```

---

## Architecture notes

### Transport
All MCP servers use **stdio JSON-RPC** (newline-delimited, MCP 2024-11-05 spec).
The orchestrator's backend clients are lightweight wrappers — they do NOT spawn additional MCP server instances; they connect directly to cdb.exe, IDA HTTP, and the x64dbg pipe.

### x64dbg named-pipe protocol
Binary framing: `MAGIC(4) + payload_len(uint32 LE) + padding(8) + JSON_payload`.
Magic bytes: `X64A`. Defined in `bridge.py` (`X64DbgBridge`) and `x64dbg_plugin.cpp`.
If you modify the framing in `bridge.py`, recompile `x64dbg_plugin.cpp`.

### IDA HTTP endpoint discovery
`ida_mcp.py` (and the orchestrator's `IDAClient`) try 6 endpoint candidates on startup: `/api/v1/py`, `/api/v1/python`, `/api/python`, `/api/1/exec`, `/python`, `/exec`. First 200-response wins; result cached for the session.

### Sessions DB
SQLite at `sessions.db`. Uses `FTS5` virtual table with triggers for incremental indexing. WAL mode enabled. Thread-safe via a module-level `threading.Lock`. Stores up to 50 000 chars per event result (truncated). `session_export_markdown` returns full Markdown directly as a string.

### Breakpoint sets
Saved by `windbg_save_breakpoints(name)` to `.windbg_mcp_breakpoints/<name>.cmd` as cdb.exe command files. Load with `windbg_load_breakpoints(name)`. Example set: `.windbg_mcp_breakpoints/rlottie_check.cmd`.

---

## Development tips

- **windbg_mcp.py** is production-hardened. Read surrounding code carefully before any change. The async cdb.exe I/O is delicate (prompt detection, timeout handling).
- **Adding IDA tools:** add a `tool_<name>` function to `ida_mcp.py`, register it in the tool list and dispatch block. Tools generate IDAPython snippets, post them to IDA's HTTP server, and parse JSON from stdout.
- **Adding x64dbg tools:** add a `_tool(...)` call in `mcp_server.py:_get_tools()`, add a handler in `_dispatch_tool()`. Implement as a `Skill` in `agent/skills/` if the logic is reusable.
- **Python version:** requires 3.11+ (uses `X | Y` union types). `aiohttp>=3.9.0` is the only hard runtime dep.
- **Running tests:** `pytest` in project root (requires `pytest-asyncio`).
