"""
Core Agent — ReAct reasoning loop for x64 debugging.

Unlike MCP servers that just proxy commands, this agent THINKS:
  Observe → Think → Act → Observe → ... until goal is reached.

The agent maintains a debugging context, plans multi-step analysis,
and uses skills (tools) to interact with x64dbg.
"""

import json
import logging
import time
import traceback
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional

from .memory import MemoryStore, DebugSession
from .skills import SkillRegistry, SkillResult

log = logging.getLogger("x64dbg.agent")


class AgentState(Enum):
    IDLE = auto()
    THINKING = auto()
    ACTING = auto()
    OBSERVING = auto()
    WAITING_USER = auto()
    ERROR = auto()


@dataclass
class Thought:
    """A single reasoning step in the ReAct loop."""
    step: int
    observation: str
    reasoning: str
    action: Optional[str] = None
    action_args: Optional[dict] = None
    result: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class AgentContext:
    """Current debugging context — persists across interactions."""
    target_process: Optional[str] = None
    target_pid: Optional[int] = None
    base_address: int = 0
    current_rip: int = 0
    breakpoints: list = field(default_factory=list)
    call_stack: list = field(default_factory=list)
    known_functions: dict = field(default_factory=dict)
    known_strings: list = field(default_factory=list)
    annotations: dict = field(default_factory=dict)  # addr -> user notes
    patterns_found: list = field(default_factory=list)
    thoughts: list = field(default_factory=list)
    goal: str = ""
    sub_goals: list = field(default_factory=list)


class DebuggerAgent:
    """
    AI-powered x64 debugger agent with ReAct reasoning.

    Key differences from plain MCP:
    1. PLANS before acting — breaks complex tasks into sub-goals
    2. REMEMBERS context — functions found, patterns seen, past sessions
    3. REASONS about results — doesn't just return raw data
    4. CHAINS actions — automatically follows leads during analysis
    5. LEARNS — stores patterns and heuristics across sessions
    """

    MAX_REACT_STEPS = 25
    MAX_ACTION_RETRIES = 3

    def __init__(self, bridge, llm_backend=None):
        self.bridge = bridge
        self.llm = llm_backend
        self.skills = SkillRegistry()
        self.memory = MemoryStore()
        self.context = AgentContext()
        self.state = AgentState.IDLE
        self._callbacks: dict[str, list[Callable]] = {}

    # ------------------------------------------------------------------
    # Event system
    # ------------------------------------------------------------------
    def on(self, event: str, callback: Callable):
        self._callbacks.setdefault(event, []).append(callback)

    def emit(self, event: str, data: Any = None):
        for cb in self._callbacks.get(event, []):
            try:
                cb(data)
            except Exception:
                log.exception("Callback for event %r raised", event)

    # ------------------------------------------------------------------
    # ReAct Loop — the brain
    # ------------------------------------------------------------------
    async def run(self, goal: str) -> list[Thought]:
        """
        Execute ReAct loop to achieve a debugging goal.

        Example goals:
          - "Find the main unpacking loop in this binary"
          - "Set breakpoint on all VirtualAlloc calls and log arguments"
          - "Trace execution from OEP to first API call"
          - "Identify anti-debug checks and patch them"
        """
        self.context.goal = goal
        self.context.thoughts = []
        self.state = AgentState.THINKING

        self.emit("goal_started", goal)

        # Load relevant memories for this type of task
        past_insights = self.memory.recall_relevant(goal)

        step = 0
        while step < self.MAX_REACT_STEPS:
            step += 1

            try:
                # 1. OBSERVE — gather current state
                observation = await self._observe()

                # 2. THINK — reason about what to do next
                thought = await self._think(step, observation, past_insights)
                self.context.thoughts.append(thought)
                self.emit("thought", thought)

                # Check if goal is achieved
                if thought.action == "__done__":
                    self.state = AgentState.IDLE
                    self.emit("goal_completed", self.context.thoughts)
                    # Save session to memory
                    self._save_session()
                    return self.context.thoughts

                # Check if we need user input
                if thought.action == "__ask_user__":
                    self.state = AgentState.WAITING_USER
                    self.emit("need_input", thought.reasoning)
                    return self.context.thoughts

                # 3. ACT — execute the chosen action
                self.state = AgentState.ACTING
                result = await self._act(thought)
                thought.result = result

                # 4. Update context based on result
                self._update_context(thought)

                self.state = AgentState.THINKING

            except Exception as e:
                error_thought = Thought(
                    step=step,
                    observation=f"Error: {e}",
                    reasoning=f"Exception occurred: {traceback.format_exc()}",
                    action="__error__",
                )
                self.context.thoughts.append(error_thought)
                self.emit("error", error_thought)

                # Don't crash — try to recover
                if step >= self.MAX_REACT_STEPS - 1:
                    self.state = AgentState.ERROR
                    break

        self.state = AgentState.IDLE
        self._save_session()
        return self.context.thoughts

    async def _observe(self) -> str:
        """Gather current debugger state for the reasoning step."""
        obs_parts = []

        if self.bridge and self.bridge.connected:
            try:
                regs = await self.bridge.get_registers()
                if regs:
                    obs_parts.append(f"RIP=0x{regs.get('rip', 0):X}")
                    obs_parts.append(f"RSP=0x{regs.get('rsp', 0):X}")
                    self.context.current_rip = regs.get('rip', 0)

                status = await self.bridge.get_debug_status()
                if status:
                    obs_parts.append(f"Status: {status}")
            except Exception as e:
                obs_parts.append(f"Bridge error: {e}")
        else:
            obs_parts.append("Debugger not connected")

        if self.context.breakpoints:
            obs_parts.append(f"Active breakpoints: {len(self.context.breakpoints)}")

        if self.context.known_functions:
            obs_parts.append(f"Known functions: {len(self.context.known_functions)}")

        return " | ".join(obs_parts) if obs_parts else "No observation available"

    async def _think(self, step: int, observation: str, past_insights: list) -> Thought:
        """
        Reasoning step — decide what to do next.

        If LLM backend is available, use it for complex reasoning.
        Otherwise, use rule-based heuristics.
        """
        if self.llm:
            return await self._think_with_llm(step, observation, past_insights)
        return self._think_heuristic(step, observation)

    async def _think_with_llm(self, step: int, observation: str, past_insights: list) -> Thought:
        """Use LLM for sophisticated reasoning about debugging steps."""
        available_skills = self.skills.list_skills()
        skill_descriptions = "\n".join(
            f"  - {s.name}: {s.description}" for s in available_skills
        )

        history = ""
        for t in self.context.thoughts[-5:]:
            history += f"  Step {t.step}: {t.reasoning}\n"
            if t.result:
                history += f"    Result: {t.result[:200]}\n"

        past_context = ""
        if past_insights:
            past_context = "Relevant past insights:\n" + "\n".join(
                f"  - {i}" for i in past_insights[:5]
            )

        prompt = f"""You are an expert x64 reverse engineer and debugger AI agent.

Goal: {self.context.goal}
Step: {step}/{self.MAX_REACT_STEPS}
Current observation: {observation}
{past_context}

Previous steps:
{history}

Available debugging skills:
{skill_descriptions}

Based on the observation and goal, decide the NEXT action.
Respond in JSON:
{{
    "reasoning": "Your analysis of the situation and why you chose this action",
    "action": "skill_name or __done__ or __ask_user__",
    "action_args": {{"arg1": "value1"}}
}}

If the goal is achieved, use action "__done__".
If you need user clarification, use action "__ask_user__".
Think step by step. Be precise with addresses (hex).
"""
        response = await self.llm.complete(prompt)

        try:
            parsed = self._extract_json(response)
            return Thought(
                step=step,
                observation=observation,
                reasoning=parsed.get("reasoning", ""),
                action=parsed.get("action"),
                action_args=parsed.get("action_args"),
            )
        except (json.JSONDecodeError, ValueError):
            return Thought(
                step=step,
                observation=observation,
                reasoning=response,
                action="__ask_user__",
            )

    @staticmethod
    def _extract_json(text: str) -> dict:
        """Extract JSON from LLM response, handling markdown code blocks."""
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines).strip()
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start:end + 1]
        return json.loads(text)

    def _think_heuristic(self, step: int, observation: str) -> Thought:
        """
        Rule-based reasoning — works WITHOUT any LLM.

        Covers 10 major reverse engineering workflows.
        """
        goal_lower = self.context.goal.lower()

        if step == 1 and not self.context.target_process:
            return Thought(
                step=step,
                observation=observation,
                reasoning="First step: identify the debugged process and its modules",
                action="get_process_info",
            )

        if step == 2:
            return Thought(
                step=step,
                observation=observation,
                reasoning="Get current register state to understand where execution is",
                action="get_registers",
            )

        workflows = [
            (["unpack", "packer", "upx", "themida", "vmprotect"], self._plan_unpacking),
            (["bossix", "isdebuggerpresent", "hide debug"], self._plan_bossix),
            (["crypto", "encrypt", "decrypt", "aes", "xor cipher", "rc4"], self._plan_crypto_analysis),
            (["inject", "injection", "hollowing", "createremotethread"], self._plan_injection_analysis),
            (["network", "c2", "callback", "beacon", "socket", "http"], self._plan_network_analysis),
            (["string", "strings"], self._plan_string_analysis),
            (["import", "iat", "api"], self._plan_import_analysis),
            (["trace", "execution flow", "control flow"], self._plan_trace),
            (["entry", "oep", "original entry", "start", "main"], self._plan_entry_analysis),
            (["breakpoint", "break", "bp"], self._plan_breakpoint),
            (["dump", "extract", "carve"], self._plan_dump),
            (["hook", "detour", "patch"], self._plan_hook_analysis),
            (["vuln", "overflow", "exploit", "bug"], self._plan_vuln_analysis),
        ]

        for keywords, planner in workflows:
            if any(kw in goal_lower for kw in keywords):
                return planner(step, observation)

        return self._plan_general_analysis(step, observation)

    def _run_plan(self, step: int, observation: str, actions: list) -> Thought:
        """Helper: execute step N from an action list."""
        idx = min(step - 3, len(actions) - 1)
        action, args, reasoning = actions[idx]
        return Thought(
            step=step,
            observation=observation,
            reasoning=reasoning,
            action=action,
            action_args=args if args else None,
        )

    def _plan_unpacking(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_memory_map", {}, "Map memory regions — look for RWX sections (sign of unpacking)"),
            ("scan_bossix", {}, "Packers often use bossix — scan first"),
            ("hide_bossix", {}, "Hide debugger to bypass packer bossix"),
            ("bp_on_api_group", {"group": "memory"}, "Set BPs on VirtualAlloc/VirtualProtect to catch unpacking"),
            ("search_pattern", {"pattern": "VirtualAlloc"}, "Find VirtualAlloc call sites in code"),
            ("run", {}, "Run to first VirtualAlloc breakpoint"),
            ("get_registers", {}, "Check RCX (size) and R9 (protection) args to VirtualAlloc"),
            ("get_memory_map", {}, "Re-check memory map — new RWX region = unpacked code"),
            ("__done__", {}, "Unpacking analysis setup complete — monitor VirtualAlloc returns for OEP"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_bossix(self, step: int, observation: str) -> Thought:
        actions = [
            ("scan_bossix", {}, "Comprehensive scan for all bossix techniques"),
            ("get_peb_info", {}, "Check PEB flags — BeingDebugged and NtGlobalFlag"),
            ("hide_bossix", {}, "Apply PEB patches to hide debugger"),
            ("get_imports", {}, "Check imports for bossix APIs"),
            ("search_pattern", {"pattern": "0F 31"}, "Search for RDTSC timing checks"),
            ("search_pattern", {"pattern": "65 48 8B 04 25 60 00 00 00"}, "Search for direct PEB access (gs:[0x60])"),
            ("bp_on_api_group", {"group": "bossix"}, "Set BPs on bossix APIs"),
            ("__done__", {}, "Bossix analysis complete — patches applied, BPs set"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_crypto_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_imports", {}, "Check for CryptoAPI / BCrypt imports"),
            ("bp_on_api_group", {"group": "crypto"}, "Set BPs on crypto APIs"),
            ("search_pattern", {"pattern": "C6 84"}, "Search for RC4 KSA initialization pattern"),
            ("search_strings", {"min_length": 8}, "Find strings — look for keys, IVs, base64"),
            ("search_pattern", {"pattern": "30"}, "Search for XOR operations (basic crypto indicator)"),
            ("get_memory_map", {}, "Check for suspicious RW regions (key/plaintext storage)"),
            ("__done__", {}, "Crypto analysis complete — BPs set on crypto APIs, patterns identified"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_injection_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_imports", {}, "Check for injection-related imports"),
            ("bp_on_api_group", {"group": "inject"}, "Set BPs on injection APIs"),
            ("bp_on_api_group", {"group": "process"}, "Set BPs on process creation APIs"),
            ("search_pattern", {"pattern": "VirtualAllocEx"}, "Find VirtualAllocEx calls"),
            ("search_pattern", {"pattern": "WriteProcessMemory"}, "Find WriteProcessMemory calls"),
            ("get_handles", {}, "Check open process handles"),
            ("__done__", {}, "Injection analysis setup complete — BPs on inject + process APIs"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_network_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_imports", {}, "Check for network API imports (Winsock, WinInet, WinHTTP)"),
            ("bp_on_api_group", {"group": "network"}, "Set BPs on network APIs"),
            ("search_strings", {"min_length": 6}, "Search for URLs, IPs, domains in strings"),
            ("search_pattern", {"pattern": "68 BB 01"}, "Search for port 443 push (common C2)"),
            ("get_handles", {}, "Check for socket handles"),
            ("__done__", {}, "Network analysis setup — BPs on network APIs, strings extracted"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_string_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("search_strings", {"min_length": 4}, "Extract all readable strings from process memory"),
            ("get_imports", {}, "Get imports to correlate with string usage"),
            ("get_modules", {}, "List modules — strings may come from loaded DLLs"),
            ("__done__", {}, "String analysis complete — strings categorized by type"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_import_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_imports", {}, "Get full import table grouped by DLL"),
            ("get_exports", {}, "Get exports from main module"),
            ("get_modules", {}, "List all loaded modules"),
            ("get_memory_map", {}, "Check for manually mapped modules (no file backing)"),
            ("__done__", {}, "Import analysis complete"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_trace(self, step: int, observation: str) -> Thought:
        actions = [
            ("disassemble", {}, "Disassemble at current RIP"),
            ("get_call_stack", {}, "Get call stack for context"),
            ("step_n", {"count": 20, "type": "over"}, "Trace 20 steps to see execution flow"),
            ("get_registers", {}, "Check register state after trace"),
            ("disassemble", {}, "Disassemble at new RIP"),
            ("__done__", {}, "Execution trace captured"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_entry_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_modules", {}, "Get main module to find entry point"),
            ("disassemble", {}, "Disassemble at current RIP (likely EP)"),
            ("analyze_function", {}, "Analyze the entry function"),
            ("get_call_stack", {}, "Get call stack"),
            ("step_n", {"count": 10, "type": "over"}, "Step through initialization"),
            ("get_registers", {}, "Check state after initialization steps"),
            ("__done__", {}, "Entry point analysis complete"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_breakpoint(self, step: int, observation: str) -> Thought:
        goal_lower = self.context.goal.lower()
        api_groups = {
            "memory": ["memory", "alloc", "virtual", "heap"],
            "file": ["file", "read", "write", "create"],
            "network": ["network", "socket", "connect", "http", "send"],
            "registry": ["registry", "reg", "hkey"],
            "process": ["process", "thread"],
            "crypto": ["crypto", "encrypt", "decrypt"],
            "inject": ["inject", "remote"],
            "bossix": ["bossix"],
        }

        actions = []
        for group, keywords in api_groups.items():
            if any(kw in goal_lower for kw in keywords):
                actions.append((
                    "bp_on_api_group", {"group": group},
                    f"Setting breakpoints on [{group}] API group",
                ))

        if not actions:
            actions.append(("bp_on_api_group", {"group": "memory"}, "Setting memory API breakpoints (default)"))

        actions.append(("get_imports", {}, "Check import table for additional BP targets"))
        actions.append(("__done__", {}, "Breakpoint setup complete"))

        return self._run_plan(step, observation, actions)

    def _plan_dump(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_modules", {}, "List modules to identify dump target"),
            ("get_memory_map", {}, "Check memory layout for interesting regions"),
            ("get_imports", {}, "Get imports (needed for IAT reconstruction post-dump)"),
            ("__done__", {}, "Ready to dump — use dump_module skill with target name"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_hook_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_modules", {}, "List modules to check for hook targets"),
            ("get_imports", {}, "Get import table — IAT hooks modify these"),
            ("search_pattern", {"pattern": "E9"}, "Search for JMP instructions at API starts (inline hooks)"),
            ("search_pattern", {"pattern": "FF 25"}, "Search for JMP [addr] trampolines"),
            ("get_memory_map", {}, "Look for RWX regions that might contain hook code"),
            ("__done__", {}, "Hook analysis complete"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_vuln_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_imports", {}, "Check for dangerous functions (strcpy, sprintf, gets)"),
            ("search_strings", {"min_length": 4}, "Find format strings, user input indicators"),
            ("search_pattern", {"pattern": "strcpy"}, "Search for strcpy usage"),
            ("search_pattern", {"pattern": "sprintf"}, "Search for sprintf usage"),
            ("get_memory_map", {}, "Check for DEP/NX status on memory regions"),
            ("get_peb_info", {}, "Check ASLR and other mitigations via PEB"),
            ("__done__", {}, "Vulnerability scan complete"),
        ]
        return self._run_plan(step, observation, actions)

    def _plan_general_analysis(self, step: int, observation: str) -> Thought:
        actions = [
            ("get_memory_map", {}, "Map process memory layout"),
            ("get_imports", {}, "Analyze import table — reveals binary capabilities"),
            ("search_strings", {"min_length": 5}, "Extract strings — find IOCs, paths, URLs"),
            ("disassemble", {}, "Disassemble at current RIP"),
            ("get_call_stack", {}, "Examine call stack"),
            ("scan_bossix", {}, "Check for bossix techniques"),
            ("analyze_function", {}, "Analyze current function in depth"),
            ("__done__", {}, "General analysis complete — see findings above"),
        ]
        return self._run_plan(step, observation, actions)

    async def _act(self, thought: Thought) -> str:
        """Execute an action via the skill registry."""
        if not thought.action or thought.action.startswith("__"):
            return ""

        skill = self.skills.get(thought.action)
        if not skill:
            return f"Unknown skill: {thought.action}"

        for attempt in range(self.MAX_ACTION_RETRIES):
            try:
                result: SkillResult = await skill.execute(
                    self.bridge,
                    self.context,
                    thought.action_args or {},
                )
                return result.to_string()
            except Exception as e:
                if attempt == self.MAX_ACTION_RETRIES - 1:
                    return f"Action failed after {self.MAX_ACTION_RETRIES} attempts: {e}"
                await self._async_sleep(0.5 * (attempt + 1))

        return "Action failed"

    def _update_context(self, thought: Thought):
        """Update agent context based on action results."""
        if not thought.result:
            return

        result_lower = thought.result.lower()
        args = thought.action_args or {}

        if thought.action in ("analyze_function", "get_exports", "get_imports"):
            self.memory.store_artifact("functions", thought.result)

        if thought.action == "search_pattern":
            self.context.patterns_found.append({
                "pattern": args.get("pattern", ""),
                "results": thought.result[:500],
            })

        if thought.action in ("set_breakpoint", "set_hw_breakpoint", "bp_on_api_group") and "error" not in result_lower:
            bp_info = args.get("address", args.get("api", args.get("group", "")))
            if bp_info:
                self.context.breakpoints.append(bp_info)

    def _save_session(self):
        """Save current debugging session to persistent memory."""
        session = DebugSession(
            target=self.context.target_process or "unknown",
            goal=self.context.goal,
            thoughts_count=len(self.context.thoughts),
            functions_found=list(self.context.known_functions.keys()),
            patterns_found=[p["pattern"] for p in self.context.patterns_found],
            insights=[t.reasoning for t in self.context.thoughts if t.action == "__done__"],
        )
        self.memory.save_session(session)

    @staticmethod
    async def _async_sleep(seconds: float):
        import asyncio
        await asyncio.sleep(seconds)


# ------------------------------------------------------------------
# LLM Backend interface
# ------------------------------------------------------------------
class LLMBackend:
    """Abstract interface for LLM backends (Claude, local models, etc.)."""

    async def complete(self, prompt: str) -> str:
        raise NotImplementedError


class ClaudeLLMBackend(LLMBackend):
    """Claude API backend for agent reasoning."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        return self._client

    async def complete(self, prompt: str) -> str:
        try:
            client = self._get_client()
            message = await client.messages.create(
                model=self.model,
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except ImportError:
            raise RuntimeError("anthropic package not installed: pip install anthropic")


class LocalLLMBackend(LLMBackend):
    """Local LLM backend (Ollama, llama.cpp, etc.) for offline use."""

    def __init__(self, endpoint: str = "http://localhost:11434/api/generate", model: str = "deepseek-r1"):
        self.endpoint = endpoint
        self.model = model
        self._session = None

    async def _get_session(self):
        if self._session is None or self._session.closed:
            import aiohttp
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120)
            )
        return self._session

    async def complete(self, prompt: str) -> str:
        session = await self._get_session()
        async with session.post(self.endpoint, json={
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }) as resp:
            data = await resp.json()
            return data.get("response", "")

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


class OpenAICompatibleBackend(LLMBackend):
    """
    OpenAI-compatible API backend.

    Works with:
    - OpenAI (api.openai.com)
    - Groq (api.groq.com/openai) — FREE tier, fast
    - Together AI (api.together.xyz)
    - OpenRouter (openrouter.ai/api) — many free models
    - LM Studio (localhost:1234)
    - vLLM (localhost:8000)
    - Any OpenAI-compatible endpoint
    """

    def __init__(self, api_key: str, endpoint: str = "https://api.openai.com/v1/chat/completions",
                 model: str = "gpt-4o-mini"):
        self.api_key = api_key
        self.endpoint = endpoint
        self.model = model
        self._session = None

    async def _get_session(self):
        if self._session is None or self._session.closed:
            import aiohttp
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
            )
        return self._session

    async def complete(self, prompt: str) -> str:
        session = await self._get_session()
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are an expert x64 reverse engineer. Respond only in JSON."},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 2048,
            "temperature": 0.1,
        }
        async with session.post(self.endpoint, json=payload) as resp:
            data = await resp.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
            error = data.get("error", {})
            if error:
                raise RuntimeError(f"API error: {error.get('message', data)}")
            return ""

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


# ------------------------------------------------------------------
# Pre-configured LLM backends for popular free/cheap providers
# ------------------------------------------------------------------
def create_groq_backend(api_key: str, model: str = "llama-3.3-70b-versatile") -> OpenAICompatibleBackend:
    """Groq — FREE tier, extremely fast inference."""
    return OpenAICompatibleBackend(
        api_key=api_key,
        endpoint="https://api.groq.com/openai/v1/chat/completions",
        model=model,
    )


def create_openrouter_backend(api_key: str, model: str = "meta-llama/llama-3.3-70b-instruct:free") -> OpenAICompatibleBackend:
    """OpenRouter — many free models available."""
    return OpenAICompatibleBackend(
        api_key=api_key,
        endpoint="https://openrouter.ai/api/v1/chat/completions",
        model=model,
    )


def create_together_backend(api_key: str, model: str = "meta-llama/Llama-3.3-70B-Instruct-Turbo") -> OpenAICompatibleBackend:
    """Together AI — cheap, fast open models."""
    return OpenAICompatibleBackend(
        api_key=api_key,
        endpoint="https://api.together.xyz/v1/chat/completions",
        model=model,
    )


def create_lmstudio_backend(model: str = "local-model") -> OpenAICompatibleBackend:
    """LM Studio — local GUI-based LLM server, no API key needed."""
    return OpenAICompatibleBackend(
        api_key="lm-studio",
        endpoint="http://localhost:1234/v1/chat/completions",
        model=model,
    )
