"""
Entry point for the x64 AI Debugger Agent.

Usage:
    # Start MCP server (stdio transport for Claude Desktop / Cursor)
    python -m agent --mcp

    # Start standalone agent with interactive CLI
    python -m agent --cli

    # Start with specific connection settings
    python -m agent --mcp --pipe "\\\\.\\pipe\\x64dbg_custom"
    python -m agent --mcp --http http://127.0.0.1:27042

    # Start with LLM backend for autonomous reasoning
    python -m agent --mcp --llm claude --api-key sk-...
    python -m agent --mcp --llm local --llm-endpoint http://localhost:11434/api/generate
"""

import argparse
import asyncio
import sys
import json


def parse_args():
    parser = argparse.ArgumentParser(
        description="x64 AI Debugger Agent — intelligent reverse engineering assistant",
    )
    parser.add_argument("--mcp", action="store_true", help="Start as MCP server (stdio transport)")
    parser.add_argument("--cli", action="store_true", help="Start interactive CLI mode")
    parser.add_argument("--pipe", default=None, help="Named pipe path (Windows)")
    parser.add_argument("--http", default=None, help="HTTP fallback URL")
    parser.add_argument("--llm", choices=["claude", "local", "groq", "openrouter", "together", "lmstudio", "openai-compat", "none"],
                       default="none",
                       help="LLM backend: claude, local (Ollama), groq (FREE), openrouter (free models), together, lmstudio, openai-compat, none (heuristics only)")
    parser.add_argument("--api-key", default=None,
                        help="API key for LLM backend (prefer the provider env var — "
                             "command-line arguments are visible to other local processes)")
    parser.add_argument("--llm-model", default=None, help="LLM model name")
    parser.add_argument("--llm-endpoint", default=None, help="LLM endpoint URL")
    parser.add_argument("--memory-path", default=None, help="Path for persistent memory storage")
    return parser.parse_args()


def create_agent(args):
    import os
    from .bridge import X64DbgBridge, BridgeProtocol
    from .core import (DebuggerAgent, ClaudeLLMBackend, LocalLLMBackend,
                       OpenAICompatibleBackend, create_groq_backend,
                       create_openrouter_backend, create_together_backend,
                       create_lmstudio_backend)
    from .memory import MemoryStore

    protocol = BridgeProtocol.NAMED_PIPE
    if args.http and not args.pipe:
        protocol = BridgeProtocol.HTTP

    bridge = X64DbgBridge(
        pipe_name=args.pipe,
        http_url=args.http,
        protocol=protocol,
    )

    llm = None
    if args.llm == "claude":
        api_key = args.api_key
        if not api_key:
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            print("Warning: No API key provided for Claude. Set ANTHROPIC_API_KEY or use --api-key", file=sys.stderr)
        else:
            model = args.llm_model or "claude-sonnet-4-20250514"
            llm = ClaudeLLMBackend(api_key, model)

    elif args.llm == "local":
        endpoint = args.llm_endpoint or "http://localhost:11434/api/generate"
        model = args.llm_model or "deepseek-r1"
        llm = LocalLLMBackend(endpoint, model)

    elif args.llm == "groq":
        api_key = args.api_key or os.environ.get("GROQ_API_KEY", "")
        if not api_key:
            print("Warning: No API key for Groq. Set GROQ_API_KEY or use --api-key", file=sys.stderr)
            print("  Get FREE key at: https://console.groq.com/keys", file=sys.stderr)
        else:
            llm = create_groq_backend(api_key, args.llm_model or "llama-3.3-70b-versatile")

    elif args.llm == "openrouter":
        api_key = args.api_key or os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            print("Warning: No API key for OpenRouter. Set OPENROUTER_API_KEY or use --api-key", file=sys.stderr)
            print("  Get key at: https://openrouter.ai/keys (free models available)", file=sys.stderr)
        else:
            llm = create_openrouter_backend(api_key, args.llm_model or "meta-llama/llama-3.3-70b-instruct:free")

    elif args.llm == "together":
        api_key = args.api_key or os.environ.get("TOGETHER_API_KEY", "")
        if not api_key:
            print("Warning: No API key for Together. Set TOGETHER_API_KEY or use --api-key", file=sys.stderr)
        else:
            llm = create_together_backend(api_key, args.llm_model or "meta-llama/Llama-3.3-70B-Instruct-Turbo")

    elif args.llm == "lmstudio":
        llm = create_lmstudio_backend(args.llm_model or "local-model")

    elif args.llm == "openai-compat":
        api_key = args.api_key or os.environ.get("LLM_API_KEY", "")
        endpoint = args.llm_endpoint or "http://localhost:8000/v1/chat/completions"
        model = args.llm_model or "default"
        llm = OpenAICompatibleBackend(api_key, endpoint, model)

    agent = DebuggerAgent(bridge, llm_backend=llm)

    if args.memory_path:
        agent.memory = MemoryStore(args.memory_path)

    return agent


async def run_mcp(agent):
    """Run as MCP server."""
    from .mcp_server import MCPServer
    server = MCPServer(agent)
    await server.run_stdio()


async def run_cli(agent):
    """Run interactive CLI."""
    print("x64 AI Debugger Agent v0.1.0")
    print("=" * 40)
    print("Commands:")
    print("  connect              — Connect to x64dbg")
    print("  status               — Show agent status")
    print("  goal <text>          — Set analysis goal and run agent")
    print("  skills               — List available skills")
    print("  exec <skill> [args]  — Execute a skill directly")
    print("  patterns [category]  — Show known patterns")
    print("  sessions             — Show past debugging sessions")
    print("  quit                 — Exit")
    print()

    print("Connecting to x64dbg...")
    connected = await agent.bridge.connect()
    if connected:
        print("Connected!")
    else:
        print("Not connected (start x64dbg with AI Agent plugin loaded)")
        print("You can still use memory/pattern features offline.\n")

    while True:
        try:
            line = await asyncio.get_running_loop().run_in_executor(None, lambda: input("agent> "))
        except (EOFError, KeyboardInterrupt):
            break

        line = line.strip()
        if not line:
            continue

        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "quit" or cmd == "exit":
            break

        elif cmd == "connect":
            connected = await agent.bridge.connect()
            print("Connected!" if connected else "Connection failed.")

        elif cmd == "status":
            print(f"State: {agent.state.name}")
            print(f"Connected: {agent.bridge.connected}")
            print(f"Target: {agent.context.target_process or 'none'}")
            print(f"Known functions: {len(agent.context.known_functions)}")
            print(f"Breakpoints: {len(agent.context.breakpoints)}")
            print(f"Patterns found: {len(agent.context.patterns_found)}")
            print(f"Past sessions: {agent.memory._knowledge.get('total_sessions', 0)}")

        elif cmd == "goal":
            if not arg:
                print("Usage: goal <analysis goal text>")
                continue
            print(f"\nRunning agent with goal: {arg}")
            print("-" * 40)
            thoughts = await agent.run(arg)
            for t in thoughts:
                print(f"\nStep {t.step}:")
                print(f"  Reasoning: {t.reasoning}")
                if t.action and not t.action.startswith("__"):
                    print(f"  Action: {t.action}")
                if t.result:
                    print(f"  Result: {t.result[:300]}")
            print("\nGoal analysis complete.")

        elif cmd == "skills":
            for skill in agent.skills.list_skills():
                print(f"  [{skill.category}] {skill.name}: {skill.description}")

        elif cmd == "exec":
            if not arg:
                print("Usage: exec <skill_name> [json_args]")
                continue
            skill_parts = arg.split(maxsplit=1)
            skill_name = skill_parts[0]
            skill_args = {}
            if len(skill_parts) > 1:
                try:
                    skill_args = json.loads(skill_parts[1])
                except json.JSONDecodeError:
                    print("Invalid JSON args")
                    continue

            skill = agent.skills.get(skill_name)
            if not skill:
                print(f"Unknown skill: {skill_name}")
                continue

            result = await skill.execute(agent.bridge, agent.context, skill_args)
            print(result.to_string())

        elif cmd == "patterns":
            category = arg if arg else None
            if category:
                patterns = agent.memory.get_patterns_by_category(category)
            else:
                patterns = agent.memory.get_all_patterns()

            for p in patterns:
                print(f"\n[{p.category}] {p.name}")
                print(f"  Pattern: {p.pattern}")
                print(f"  {p.description}")

        elif cmd == "sessions":
            sessions = agent.memory.get_sessions()
            if not sessions:
                print("No past sessions.")
            for s in sessions:
                print(f"  [{s.session_id}] {s.target}: {s.goal}")
                print(f"    Functions: {len(s.functions_found)}, Patterns: {len(s.patterns_found)}")

        else:
            print(f"Unknown command: {cmd}. Type 'skills' for available commands.")

    print("\nGoodbye!")
    await agent.bridge.disconnect()


def main():
    args = parse_args()

    if not args.mcp and not args.cli:
        args.mcp = True  # Default to MCP mode

    agent = create_agent(args)

    if args.mcp:
        asyncio.run(run_mcp(agent))
    else:
        asyncio.run(run_cli(agent))


if __name__ == "__main__":
    main()
