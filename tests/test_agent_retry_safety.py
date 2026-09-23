import pytest

from agent.core import DebuggerAgent, Thought
from agent.skills import SkillDefinition, SkillRegistry, SkillResult


@pytest.mark.asyncio
async def test_mutating_action_exception_is_not_retried():
    agent = DebuggerAgent(bridge=None)
    calls = 0

    async def mutate(_bridge, _context, _args):
        nonlocal calls
        calls += 1
        raise RuntimeError("response lost after side effect")

    agent.skills.register(
        SkillDefinition(
            name="dangerous",
            description="stateful operation",
            execute=mutate,
            effect="mutating",
        )
    )

    result = await agent._act(Thought(
        step=1,
        observation="",
        reasoning="",
        action="dangerous",
    ))

    assert calls == 1
    assert result.success is False
    assert result.error_code == "ACTION_EXCEPTION"
    assert "not retried" in result.error_hint.lower()


@pytest.mark.asyncio
async def test_read_only_action_can_retry_transient_exception():
    agent = DebuggerAgent(bridge=None)
    calls = 0

    async def read(_bridge, _context, _args):
        nonlocal calls
        calls += 1
        if calls < 3:
            raise RuntimeError("transient transport failure")
        return SkillResult(success=True, summary="ok", data={"value": 1})

    async def no_sleep(_seconds):
        return None

    agent._async_sleep = no_sleep
    agent.skills.register(
        SkillDefinition(
            name="safe_read",
            description="read-only operation",
            execute=read,
            effect="read_only",
        )
    )

    result = await agent._act(Thought(
        step=1,
        observation="",
        reasoning="",
        action="safe_read",
    ))

    assert calls == 3
    assert result.success is True
    assert result.data == {"value": 1}


def test_unclassified_skill_defaults_to_no_retry():
    async def execute(_bridge, _context, _args):
        return SkillResult(success=True)

    skill = SkillDefinition(
        name="new_skill",
        description="new skill with no effect classification",
        execute=execute,
    )
    assert skill.effect == "mutating"
    assert skill.retry_safe is False


def test_builtin_side_effect_metadata_is_conservative():
    registry = SkillRegistry()

    assert registry.get("get_registers").effect == "read_only"
    assert registry.get("read_memory").effect == "read_only"
    assert registry.get("set_register").effect == "idempotent"
    assert registry.get("set_breakpoint").effect == "idempotent"

    for name in (
        "run",
        "step_n",
        "write_memory",
        "allocate_memory",
        "execute_command",
        "run_script",
        "hide_bossix",
        "patch_bossix",
    ):
        skill = registry.get(name)
        assert skill.effect == "mutating"
        assert skill.retry_safe is False


def test_context_updates_use_structured_success_not_error_word_heuristic():
    agent = DebuggerAgent(bridge=None)

    failed = Thought(
        step=1,
        observation="",
        reasoning="",
        action="set_breakpoint",
        action_args={"address": "0x401000"},
        result="looks fine",
        skill_result=SkillResult(success=False, summary="failed without the magic word"),
    )
    agent._update_context(failed)
    assert agent.context.breakpoints == []

    succeeded = Thought(
        step=2,
        observation="",
        reasoning="",
        action="set_breakpoint",
        action_args={"address": "0x402000"},
        result="success summary containing the word error as harmless text",
        skill_result=SkillResult(success=True, summary="error string in a successful result"),
    )
    agent._update_context(succeeded)
    assert agent.context.breakpoints == ["0x402000"]


def test_heuristic_planner_stops_after_failed_step():
    agent = DebuggerAgent(bridge=None)
    agent.context.goal = "general analysis"
    agent.context.thoughts = [
        Thought(
            step=3,
            observation="",
            reasoning="",
            action="get_memory_map",
            result="failed",
            skill_result=SkillResult(success=False, summary="transport failed"),
        )
    ]

    next_thought = agent._think_heuristic(4, "Status: paused")
    assert next_thought.action == "__ask_user__"
    assert "refusing to advance" in next_thought.reasoning.lower()
