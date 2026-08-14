"""
Debugging Skills — Modular tool system for the AI agent.

Each skill is a self-contained debugging capability that the agent
can invoke during its ReAct reasoning loop.

Skills are more than simple API wrappers — they:
1. Validate inputs and provide meaningful error messages
2. Post-process results for the agent to understand
3. Can chain sub-operations (e.g., "analyze_function" disassembles + finds xrefs)
4. Return structured data the agent can reason about
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Union
import json


def parse_address(value: Union[str, int, None], fallback: int = 0) -> int:
    """Parse an address argument that could be int, hex string, or None."""
    if value is None:
        return fallback
    if isinstance(value, int):
        return value
    value = value.strip()
    if not value:
        return fallback
    try:
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        # Try hex first if it looks like hex (all hex chars)
        if all(c in "0123456789abcdefABCDEF" for c in value) and len(value) >= 6:
            return int(value, 16)
        return int(value)
    except ValueError:
        return fallback


def parse_int(value: Union[str, int, None], fallback: int = 0) -> int:
    """Parse an int argument that may be a decimal or ``0x``-prefixed hex string."""
    if value is None:
        return fallback
    if isinstance(value, int):
        return value
    value = value.strip()
    if not value:
        return fallback
    try:
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return fallback


@dataclass
class SkillResult:
    """Result of a skill execution."""
    success: bool
    data: Any = None
    summary: str = ""
    details: str = ""
    suggestions: list = field(default_factory=list)  # next actions the agent might take
    error_code: str = ""  # machine-readable error code (e.g. MISSING_ARGUMENT)
    error_hint: str = ""  # actionable fix suggestion for the AI model

    def to_string(self) -> str:
        parts = []
        if self.summary:
            parts.append(self.summary)
        if self.details:
            parts.append(self.details)
        if self.suggestions:
            parts.append("Suggestions: " + ", ".join(self.suggestions))
        return "\n".join(parts) if parts else str(self.data)

    def to_json(self) -> dict:
        """Return structured JSON for MCP tool responses.

        AI models parse structured JSON far more reliably than narrative text.
        This method provides a consistent schema across all skill results.
        """
        result = {
            "success": self.success,
            "summary": self.summary,
        }
        if not self.success:
            result["error"] = {
                "code": self.error_code or "SKILL_FAILED",
                "message": self.summary,
                "hint": self.error_hint or "",
            }
        if self.data is not None:
            result["data"] = self._serialize_data(self.data)
        if self.details:
            result["details"] = self.details
        if self.suggestions:
            result["suggested_next_tools"] = self.suggestions
        return result

    @staticmethod
    def _serialize_data(data: Any) -> Any:
        """Make data JSON-serializable."""
        if isinstance(data, (str, int, float, bool, type(None))):
            return data
        if isinstance(data, bytes):
            return data.hex()
        if isinstance(data, dict):
            return {str(k): SkillResult._serialize_data(v) for k, v in data.items()}
        if isinstance(data, (list, tuple)):
            return [SkillResult._serialize_data(item) for item in data]
        return str(data)


@dataclass
class SkillDefinition:
    """Metadata about a registered skill."""
    name: str
    description: str
    args_schema: dict = field(default_factory=dict)
    category: str = "general"
    execute: Callable = None


class SkillRegistry:
    """Registry of available debugging skills."""

    def __init__(self):
        self._skills: dict[str, SkillDefinition] = {}
        self._register_builtins()

    def register(self, skill: SkillDefinition):
        self._skills[skill.name] = skill

    def get(self, name: str) -> Optional[SkillDefinition]:
        return self._skills.get(name)

    def list_skills(self) -> list[SkillDefinition]:
        return list(self._skills.values())

    def list_by_category(self, category: str) -> list[SkillDefinition]:
        return [s for s in self._skills.values() if s.category == category]

    def _register_builtins(self):
        """Register all built-in debugging skills."""
        from .execution import register_execution_skills
        from .memory_ops import register_memory_skills
        from .analysis import register_analysis_skills
        from .breakpoints import register_breakpoint_skills
        from .process import register_process_skills
        from .bossix import register_bossix_skills

        register_execution_skills(self)
        register_memory_skills(self)
        register_analysis_skills(self)
        register_breakpoint_skills(self)
        register_process_skills(self)
        register_bossix_skills(self)
