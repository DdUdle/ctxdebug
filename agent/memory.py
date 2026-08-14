"""
Memory System — Persistent debugging context across sessions.

Unlike MCP servers that forget everything between requests, this system:
1. Stores debugging session history (what was analyzed, what was found)
2. Indexes discovered functions, strings, patterns
3. Recalls relevant context for similar future tasks
4. Learns common patterns (packer signatures, anti-debug tricks)
"""

import json
import logging
import os
import time
import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

log = logging.getLogger("x64dbg.memory")


@dataclass
class DebugSession:
    """A completed debugging session."""
    target: str
    goal: str
    thoughts_count: int
    functions_found: list = field(default_factory=list)
    patterns_found: list = field(default_factory=list)
    insights: list = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    session_id: str = ""

    def __post_init__(self):
        if not self.session_id:
            self.session_id = hashlib.sha256(
                f"{self.target}:{self.goal}:{self.timestamp}".encode()
            ).hexdigest()[:12]


@dataclass
class FunctionInfo:
    """Discovered function metadata."""
    address: int
    name: str
    size: int = 0
    calling_convention: str = ""
    args_count: int = 0
    is_api: bool = False
    module: str = ""
    xref_count: int = 0
    tags: list = field(default_factory=list)


@dataclass
class PatternSignature:
    """Known binary pattern (packer, compiler, etc.)."""
    name: str
    pattern: str
    category: str
    description: str = ""
    confidence: float = 1.0


class MemoryStore:
    """
    Persistent memory for the debugging agent.

    Storage layout:
      ~/.x64ai/
        sessions/          — past debugging sessions
        patterns/          — known binary patterns
        functions/         — discovered function database
        artifacts/         — raw data from analysis
        knowledge.json     — aggregated knowledge base
    """

    DEFAULT_PATH = os.path.expanduser("~/.x64ai")

    def __init__(self, base_path: str = None):
        self.base_path = Path(base_path or self.DEFAULT_PATH)
        self._ensure_dirs()
        self._knowledge = self._load_knowledge()
        self._builtin_patterns = self._init_builtin_patterns()
        self._load_custom_patterns()

    def _ensure_dirs(self):
        for subdir in ["sessions", "patterns", "functions", "artifacts"]:
            (self.base_path / subdir).mkdir(parents=True, exist_ok=True)

    def _load_knowledge(self) -> dict:
        kb_path = self.base_path / "knowledge.json"
        if kb_path.exists():
            try:
                return json.loads(kb_path.read_text())
            except (json.JSONDecodeError, OSError) as e:
                log.warning("Could not read knowledge base %s: %s; starting fresh", kb_path, e)
        return {
            "total_sessions": 0,
            "common_goals": {},
            "known_targets": {},
            "learned_patterns": [],
        }

    def _save_knowledge(self):
        kb_path = self.base_path / "knowledge.json"
        kb_path.write_text(json.dumps(self._knowledge, indent=2))

    def save_session(self, session: DebugSession):
        """Save a completed debugging session."""
        path = self.base_path / "sessions" / f"{session.session_id}.json"
        path.write_text(json.dumps(asdict(session), indent=2))

        self._knowledge["total_sessions"] += 1
        goal_key = session.goal[:50]
        self._knowledge["common_goals"][goal_key] = (
            self._knowledge["common_goals"].get(goal_key, 0) + 1
        )
        if session.target != "unknown":
            self._knowledge["known_targets"][session.target] = {
                "last_analyzed": session.timestamp,
                "sessions": self._knowledge["known_targets"].get(
                    session.target, {}
                ).get("sessions", 0) + 1,
            }
        self._save_knowledge()

    def get_sessions(self, target: str = None, limit: int = 10) -> list[DebugSession]:
        """Retrieve past sessions, optionally filtered by target."""
        sessions = []
        session_dir = self.base_path / "sessions"
        files = sorted(session_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)

        for f in files[:limit * 2]:
            try:
                data = json.loads(f.read_text())
                session = DebugSession(**data)
                if target is None or session.target == target:
                    sessions.append(session)
                    if len(sessions) >= limit:
                        break
            except (json.JSONDecodeError, TypeError, OSError) as e:
                log.warning("Skipping unreadable session file %s: %s", f, e)
                continue

        return sessions

    def save_function(self, func: FunctionInfo):
        """Store discovered function information."""
        path = self.base_path / "functions" / f"0x{func.address:X}.json"
        path.write_text(json.dumps(asdict(func), indent=2))

    def get_function(self, address: int) -> Optional[FunctionInfo]:
        path = self.base_path / "functions" / f"0x{address:X}.json"
        if path.exists():
            try:
                data = json.loads(path.read_text())
                return FunctionInfo(**data)
            except (json.JSONDecodeError, TypeError) as e:
                log.warning("Corrupt function file %s: %s", path, e)
        return None

    def search_functions(self, tag: str = None, name_pattern: str = None) -> list[FunctionInfo]:
        """Search function database."""
        results = []
        for f in (self.base_path / "functions").glob("*.json"):
            try:
                data = json.loads(f.read_text())
                func = FunctionInfo(**data)
                if tag and tag not in func.tags:
                    continue
                if name_pattern and name_pattern.lower() not in func.name.lower():
                    continue
                results.append(func)
            except (json.JSONDecodeError, TypeError) as e:
                log.warning("Skipping unreadable function file %s: %s", f, e)
                continue
        return results

    def store_artifact(self, category: str, data: str, name: str = None):
        """Store raw analysis data."""
        if not name:
            name = hashlib.sha256(data.encode()).hexdigest()[:8]
        path = self.base_path / "artifacts" / f"{category}_{name}.txt"
        path.write_text(data)

    def get_artifact(self, category: str, name: str) -> Optional[str]:
        path = self.base_path / "artifacts" / f"{category}_{name}.txt"
        return path.read_text() if path.exists() else None

    def recall_relevant(self, goal: str) -> list[str]:
        """Recall insights relevant to a given goal."""
        goal_words = set(goal.lower().split())
        relevant_keywords = {
            "unpack": ["virtualalloc", "virtualprotect", "oep", "section", "rwx", "packer"],
            "anti-debug": ["isdebuggerpresent", "peb", "ntquery", "timing", "checkremote"],
            "crypto": ["aes", "xor", "rc4", "encrypt", "decrypt", "key", "iv"],
            "inject": ["createremotethread", "writeprocessmemory", "ntmapviewofsection"],
            "hook": ["detour", "trampoline", "iat", "eat", "inline", "patch"],
            "network": ["socket", "connect", "send", "recv", "http", "dns", "c2"],
        }

        matched_categories = []
        for category, keywords in relevant_keywords.items():
            if any(w in goal_words for w in [category] + keywords):
                matched_categories.append(category)

        insights = []

        for session in self.get_sessions(limit=20):
            session_text = f"{session.goal} {' '.join(session.insights)}".lower()
            if any(cat in session_text for cat in matched_categories):
                insights.extend(session.insights)
            elif any(word in session_text for word in goal_words if len(word) > 3):
                insights.extend(session.insights)

        for pattern in self._builtin_patterns:
            if pattern.category in matched_categories:
                insights.append(f"Known pattern: {pattern.name} — {pattern.description}")

        return insights[:10]

    def _init_builtin_patterns(self) -> list[PatternSignature]:
        """Common binary patterns that the agent knows about."""
        return [
            PatternSignature(
                name="UPX Unpacker Loop",
                pattern="8A 06 46 88 07 47 01 DB",
                category="packer",
                description="UPX decompression loop — set BP after loop to find OEP",
            ),
            PatternSignature(
                name="IsDebuggerPresent (PEB check)",
                pattern="64 A1 30 00 00 00 0F B6 40 02",
                category="anti-debug",
                description="Direct PEB.BeingDebugged check via TEB->PEB",
            ),
            PatternSignature(
                name="IsDebuggerPresent (x64 PEB)",
                pattern="65 48 8B 04 25 60 00 00 00 0F B6 40 02",
                category="anti-debug",
                description="x64 PEB.BeingDebugged check via gs:[0x60]",
            ),
            PatternSignature(
                name="NtGlobalFlag Check",
                pattern="65 48 8B 04 25 60 00 00 00 8B 40 BC",
                category="anti-debug",
                description="NtGlobalFlag check — 0x70 when debugged",
            ),
            PatternSignature(
                name="RDTSC Timing Check",
                pattern="0F 31 48 C1 E2 20 48 09 D0",
                category="anti-debug",
                description="RDTSC-based timing check — compare delta to threshold",
            ),
            PatternSignature(
                name="XOR Decrypt Loop",
                pattern="30 ?? 4? FF C? ?? ?? 75",
                category="crypto",
                description="Simple XOR decryption loop — check key register",
            ),
            PatternSignature(
                name="RC4 KSA",
                pattern="C6 84 ?? ?? ?? ?? ?? 00 4? FF C? 81 F? 00 01 00 00",
                category="crypto",
                description="RC4 Key Scheduling Algorithm initialization",
            ),
            PatternSignature(
                name="VirtualAlloc RWX",
                pattern="41 B9 40 00 00 00 41 B8 00 30 00 00",
                category="packer",
                description="VirtualAlloc with PAGE_EXECUTE_READWRITE (0x40) — likely unpacking",
            ),
            PatternSignature(
                name="Stack String Construction",
                pattern="C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ??",
                category="obfuscation",
                description="Stack string construction — strings built on stack to avoid static detection",
            ),
            PatternSignature(
                name="CreateRemoteThread Injection",
                pattern="FF 15 ?? ?? ?? ?? 48 85 C0 ?? ?? FF 15",
                category="inject",
                description="Possible CreateRemoteThread-based process injection",
            ),
            PatternSignature(
                name="Syscall Stub",
                pattern="4C 8B D1 B8 ?? ?? 00 00 0F 05 C3",
                category="evasion",
                description="Direct syscall stub — bypasses API hooks",
            ),
            PatternSignature(
                name="Heaven's Gate (x64 transition)",
                pattern="6A 33 E8 00 00 00 00 83 04 24 05 CB",
                category="evasion",
                description="Heaven's Gate — WoW64 x86->x64 transition",
            ),
        ]

    def get_patterns_by_category(self, category: str) -> list[PatternSignature]:
        return [p for p in self._builtin_patterns if p.category == category]

    def get_all_patterns(self) -> list[PatternSignature]:
        return self._builtin_patterns.copy()

    def _load_custom_patterns(self):
        """Load user-saved custom patterns from disk."""
        patterns_file = self.base_path / "patterns" / "custom.json"
        if patterns_file.exists():
            try:
                data = json.loads(patterns_file.read_text())
                for item in data:
                    try:
                        pattern = PatternSignature(**item)
                        if not any(p.name == pattern.name and p.pattern == pattern.pattern
                                   for p in self._builtin_patterns):
                            self._builtin_patterns.append(pattern)
                    except TypeError as e:
                        log.warning("Skipping malformed custom pattern %r: %s", item, e)
                        continue
            except (json.JSONDecodeError, OSError) as e:
                log.warning("Could not load custom patterns from %s: %s", patterns_file, e)

    def add_custom_pattern(self, pattern: PatternSignature):
        """Add a user-discovered pattern to the knowledge base."""
        if any(p.name == pattern.name and p.pattern == pattern.pattern
               for p in self._builtin_patterns):
            return
        self._builtin_patterns.append(pattern)
        patterns_file = self.base_path / "patterns" / "custom.json"
        existing = []
        if patterns_file.exists():
            try:
                existing = json.loads(patterns_file.read_text())
            except json.JSONDecodeError as e:
                log.warning("Custom patterns file %s is corrupt (%s); overwriting", patterns_file, e)
        existing.append(asdict(pattern))
        patterns_file.write_text(json.dumps(existing, indent=2))
