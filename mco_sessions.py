#!/usr/bin/env python3
"""
MCO Session Intelligence — Record, search, replay, and export debug sessions.
Wraps all MCO MCP calls with SQLite  and full-text search.

Usage:
    python mco_sessions.py                 # stdio MCP server
    claude mcp add mco-sessions -- python "C:\\path\\mco_sessions.py"

Environment:
    MCO_SESSIONS_DB  — path to SQLite DB (default: ./sessions.db)
"""

import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from mco_common import serve_stdio, text_error, text_result

DB_PATH = os.environ.get(
    "MCO_SESSIONS_DB",
    str(Path(__file__).parent / "sessions.db")
)

# ─────────────────────────────────────────────────────────────
#  Database
# ─────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    target          TEXT,
    debugger        TEXT,
    started_at      REAL    NOT NULL,
    ended_at        REAL,
    notes           TEXT,
    tool_call_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp   REAL    NOT NULL,
    tool_name   TEXT    NOT NULL,
    args_json   TEXT,
    result_text TEXT,
    duration_ms INTEGER
);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    result_text,
    tool_name,
    content='events',
    content_rowid='id'
);

CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, result_text, tool_name)
    VALUES (new.id, new.result_text, new.tool_name);
END;

CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, result_text, tool_name)
    VALUES ('delete', old.id, old.result_text, old.tool_name);
END;

CREATE TRIGGER IF NOT EXISTS events_fts_update AFTER UPDATE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, result_text, tool_name)
    VALUES ('delete', old.id, old.result_text, old.tool_name);
    INSERT INTO events_fts(rowid, result_text, tool_name)
    VALUES (new.id, new.result_text, new.tool_name);
END;
"""

_lock = threading.Lock()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with _lock:
        conn = get_db()
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()


# ─────────────────────────────────────────────────────────────
#  Session Intelligence
# ─────────────────────────────────────────────────────────────

_current_session_id: int | None = None


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)}s"
    m, s = divmod(int(seconds), 60)
    return f"{m}m {s}s"


def _extract_addresses(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r'\b0x[0-9a-fA-F]{4,16}\b', text or "")))


def _extract_functions(text: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r'\b\w+!\w+\b', text or "")))


def _snippet(text: str, query: str, ctx: int = 60) -> str:
    idx = text.lower().find(query.lower())
    if idx == -1:
        return text[:120]
    start = max(0, idx - ctx)
    end = min(len(text), idx + len(query) + ctx)
    return ("…" if start > 0 else "") + text[start:end] + ("…" if end < len(text) else "")


class SessionManager:

    # ── Session lifecycle ────────────────────────────────────

    def session_start(self, name: str, target: str = "", debugger: str = "") -> dict:
        global _current_session_id
        with _lock:
            conn = get_db()
            cur = conn.execute(
                "INSERT INTO sessions (name, target, debugger, started_at) VALUES (?,?,?,?)",
                (name, target or "", debugger or "", time.time())
            )
            sid = cur.lastrowid
            conn.commit()
            conn.close()
        _current_session_id = sid
        return {
            "session_id": sid,
            "name": name,
            "target": target,
            "debugger": debugger,
            "message": f"Session #{sid} '{name}' started. Current session set."
        }

    def session_end(self, session_id: int | None = None, notes: str = "") -> dict:
        global _current_session_id
        sid = session_id or _current_session_id
        if not sid:
            return {"error": "No active session. Call session_start first."}
        with _lock:
            conn = get_db()
            conn.execute(
                "UPDATE sessions SET ended_at=?, notes=? WHERE id=?",
                (time.time(), notes, sid)
            )
            conn.commit()
            row = conn.execute(
                "SELECT name, started_at, ended_at, tool_call_count FROM sessions WHERE id=?",
                (sid,)
            ).fetchone()
            conn.close()
        if _current_session_id == sid:
            _current_session_id = None
        duration = row["ended_at"] - row["started_at"]
        return {
            "session_id": sid,
            "name": row["name"],
            "duration": _fmt_duration(duration),
            "tool_calls": row["tool_call_count"],
            "notes": notes,
            "message": "Session ended."
        }

    def session_list(self, limit: int = 20) -> dict:
        with _lock:
            conn = get_db()
            rows = conn.execute(
                """SELECT id, name, target, debugger, started_at, ended_at, tool_call_count
                   FROM sessions ORDER BY id DESC LIMIT ?""",
                (min(limit, 100),)
            ).fetchall()
            conn.close()
        sessions = []
        for r in rows:
            duration = None
            if r["ended_at"]:
                duration = _fmt_duration(r["ended_at"] - r["started_at"])
            sessions.append({
                "id": r["id"],
                "name": r["name"],
                "target": r["target"],
                "debugger": r["debugger"],
                "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["started_at"])),
                "duration": duration or "in progress",
                "tool_calls": r["tool_call_count"],
                "active": r["id"] == _current_session_id
            })
        return {"sessions": sessions, "total": len(sessions), "current_session_id": _current_session_id}

    def session_delete(self, session_id: int) -> dict:
        global _current_session_id
        with _lock:
            conn = get_db()
            row = conn.execute("SELECT name FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not row:
                conn.close()
                return {"error": f"Session #{session_id} not found"}
            conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))
            conn.commit()
            conn.close()
        if _current_session_id == session_id:
            _current_session_id = None
        return {"deleted": session_id, "name": row["name"]}

    # ── Recording ────────────────────────────────────────────

    def session_record(self, tool_name: str, args: dict, result: str,
                       duration_ms: int = 0, session_id: int | None = None) -> dict:
        sid = session_id or _current_session_id
        if not sid:
            return {"error": "No active session. Call session_start first."}
        result_truncated = (result or "")[:50_000]
        with _lock:
            conn = get_db()
            conn.execute(
                "INSERT INTO events (session_id, timestamp, tool_name, args_json, result_text, duration_ms) "
                "VALUES (?,?,?,?,?,?)",
                (sid, time.time(), tool_name, json.dumps(args), result_truncated, duration_ms)
            )
            conn.execute(
                "UPDATE sessions SET tool_call_count = tool_call_count + 1 WHERE id=?", (sid,)
            )
            conn.commit()
            conn.close()
        return {"recorded": True, "session_id": sid, "tool": tool_name}

    # ── Search & Query ───────────────────────────────────────

    def session_search(self, query: str, debugger: str = "",
                       date_from: str = "") -> dict:
        with _lock:
            conn = get_db()
            params: list = [query]
            date_clause = ""
            if date_from:
                try:
                    ts = time.mktime(time.strptime(date_from, "%Y-%m-%d"))
                    date_clause = "AND s.started_at >= ?"
                    params.append(ts)
                except ValueError:
                    pass
            debugger_clause = ""
            if debugger:
                debugger_clause = "AND s.debugger = ?"
                params.append(debugger)

            rows = conn.execute(f"""
                SELECT e.id, e.session_id, e.tool_name, e.result_text, e.timestamp,
                       s.name, s.target, s.debugger
                FROM events_fts fts
                JOIN events e ON e.id = fts.rowid
                JOIN sessions s ON s.id = e.session_id
                WHERE events_fts MATCH ?
                {date_clause} {debugger_clause}
                ORDER BY e.timestamp DESC
                LIMIT 50
            """, params).fetchall()
            conn.close()

        results = []
        for r in rows:
            results.append({
                "session_id": r["session_id"],
                "session_name": r["name"],
                "target": r["target"],
                "debugger": r["debugger"],
                "tool": r["tool_name"],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["timestamp"])),
                "snippet": _snippet(r["result_text"] or "", query)
            })
        return {"query": query, "matches": results, "count": len(results)}

    def session_replay(self, session_id: int) -> dict:
        with _lock:
            conn = get_db()
            session = conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            if not session:
                conn.close()
                return {"error": f"Session #{session_id} not found"}
            events = conn.execute(
                "SELECT * FROM events WHERE session_id=? ORDER BY timestamp",
                (session_id,)
            ).fetchall()
            conn.close()

        t0 = session["started_at"]
        return {
            "session_id": session_id,
            "name": session["name"],
            "target": session["target"],
            "debugger": session["debugger"],
            "events": [
                {
                    "offset_sec": round(e["timestamp"] - t0, 1),
                    "tool": e["tool_name"],
                    "args": json.loads(e["args_json"] or "{}"),
                    "result": (e["result_text"] or "")[:2000],
                    "duration_ms": e["duration_ms"]
                }
                for e in events
            ],
            "total_events": len(events)
        }

    def session_find_address(self, address: str) -> dict:
        normalized = address.lower().replace("0x", "")
        query = f"0x{normalized}"
        return self.session_search(query)

    def session_find_function(self, name: str) -> dict:
        return self.session_search(name)

    # ── Intelligence & Reporting ─────────────────────────────

    def session_summary(self, session_id: int) -> dict:
        with _lock:
            conn = get_db()
            session = conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            if not session:
                conn.close()
                return {"error": f"Session #{session_id} not found"}
            events = conn.execute(
                "SELECT tool_name, result_text FROM events WHERE session_id=? ORDER BY timestamp",
                (session_id,)
            ).fetchall()
            conn.close()

        tool_counts: dict[str, int] = {}
        all_text = ""
        key_findings = []

        for e in events:
            tool_counts[e["tool_name"]] = tool_counts.get(e["tool_name"], 0) + 1
            text = e["result_text"] or ""
            all_text += " " + text
            for line in text.splitlines():
                if any(kw in line.upper() for kw in
                       ["ERROR", "CRITICAL", "WARNING", "FOUND", "DETECTED", "CORRUPT"]):
                    key_findings.append({"tool": e["tool_name"], "line": line.strip()[:200]})

        top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        duration = None
        if session["ended_at"]:
            duration = session["ended_at"] - session["started_at"]

        return {
            "session_id": session_id,
            "name": session["name"],
            "target": session["target"],
            "debugger": session["debugger"],
            "duration_seconds": round(duration, 1) if duration else None,
            "duration_human": _fmt_duration(duration) if duration else "in progress",
            "tool_call_count": session["tool_call_count"],
            "top_tools": [{"name": n, "count": c} for n, c in top_tools],
            "addresses_found": _extract_addresses(all_text)[:30],
            "functions_found": _extract_functions(all_text)[:30],
            "key_findings": key_findings[:20]
        }

    def session_export_markdown(self, session_id: int) -> str:
        with _lock:
            conn = get_db()
            session = conn.execute(
                "SELECT * FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            if not session:
                conn.close()
                return f"ERROR: Session #{session_id} not found"
            events = conn.execute(
                "SELECT * FROM events WHERE session_id=? ORDER BY timestamp",
                (session_id,)
            ).fetchall()
            conn.close()

        t0 = session["started_at"]
        duration = ""
        if session["ended_at"]:
            duration = _fmt_duration(session["ended_at"] - t0)

        tool_counts: dict[str, int] = {}
        all_text = ""
        for e in events:
            tool_counts[e["tool_name"]] = tool_counts.get(e["tool_name"], 0) + 1
            all_text += " " + (e["result_text"] or "")

        lines = [
            f"# Session: {session['name']}",
            f"",
            f"**Target:** `{session['target'] or 'N/A'}`  "
            f"**Debugger:** {session['debugger'] or 'N/A'}  "
            f"**Duration:** {duration or 'in progress'}  ",
            f"**Started:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t0))}  "
            f"**Tool Calls:** {session['tool_call_count']}",
            f"",
        ]

        if session["notes"]:
            lines += [f"**Notes:** {session['notes']}", ""]

        lines += ["---", "", "## Timeline", ""]

        for e in events:
            offset = round(e["timestamp"] - t0, 1)
            mm = int(offset // 60)
            ss = int(offset % 60)
            args = json.loads(e["args_json"] or "{}")
            args_str = json.dumps(args) if args else "{}"
            result = (e["result_text"] or "").strip()[:3000]

            lines += [
                f"### [{mm:02d}:{ss:02d}] `{e['tool_name']}`",
                f"**Args:** `{args_str}`",
                "```",
                result,
                "```",
                ""
            ]

        # Key addresses
        addrs = _extract_addresses(all_text)
        if addrs:
            lines += ["---", "", "## Key Addresses Mentioned", ""]
            addr_counts = {}
            for a in re.findall(r'\b0x[0-9a-fA-F]{4,16}\b', all_text):
                addr_counts[a] = addr_counts.get(a, 0) + 1
            for addr, cnt in sorted(addr_counts.items(), key=lambda x: x[1], reverse=True)[:15]:
                lines.append(f"- `{addr}` — mentioned {cnt}x")
            lines.append("")

        # Tools table
        if tool_counts:
            lines += ["## Tools Used", "", "| Tool | Calls |", "|------|-------|"]
            for name, cnt in sorted(tool_counts.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| `{name}` | {cnt} |")
            lines.append("")

        lines += ["---", "", "*Generated by MCO Session Intelligence*"]

        return "\n".join(lines)

    def session_stats(self) -> dict:
        with _lock:
            conn = get_db()
            total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            top_tools = conn.execute(
                "SELECT tool_name, COUNT(*) as cnt FROM events GROUP BY tool_name ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
            top_targets = conn.execute(
                "SELECT target, COUNT(*) as cnt FROM sessions WHERE target != '' "
                "GROUP BY target ORDER BY cnt DESC LIMIT 5"
            ).fetchall()
            by_debugger = conn.execute(
                "SELECT debugger, COUNT(*) as cnt FROM sessions WHERE debugger != '' "
                "GROUP BY debugger ORDER BY cnt DESC"
            ).fetchall()
            conn.close()

        return {
            "total_sessions": total_sessions,
            "total_tool_calls": total_events,
            "top_tools": [{"name": r["tool_name"], "count": r["cnt"]} for r in top_tools],
            "top_targets": [{"target": r["target"], "sessions": r["cnt"]} for r in top_targets],
            "by_debugger": [{"debugger": r["debugger"], "sessions": r["cnt"]} for r in by_debugger]
        }

    def session_diff(self, session_id_a: int, session_id_b: int) -> dict:
        with _lock:
            conn = get_db()
            sa = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id_a,)).fetchone()
            sb = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id_b,)).fetchone()
            if not sa:
                conn.close()
                return {"error": f"Session #{session_id_a} not found"}
            if not sb:
                conn.close()
                return {"error": f"Session #{session_id_b} not found"}
            ea = conn.execute(
                "SELECT tool_name FROM events WHERE session_id=? ORDER BY timestamp",
                (session_id_a,)
            ).fetchall()
            eb = conn.execute(
                "SELECT tool_name FROM events WHERE session_id=? ORDER BY timestamp",
                (session_id_b,)
            ).fetchall()
            conn.close()

        seq_a = [r["tool_name"] for r in ea]
        seq_b = [r["tool_name"] for r in eb]
        set_a = set(seq_a)
        set_b = set(seq_b)

        counts_a: dict[str, int] = {}
        counts_b: dict[str, int] = {}
        for t in seq_a:
            counts_a[t] = counts_a.get(t, 0) + 1
        for t in seq_b:
            counts_b[t] = counts_b.get(t, 0) + 1

        only_in_a = sorted(set_a - set_b)
        only_in_b = sorted(set_b - set_a)
        in_both = sorted(set_a & set_b)

        count_diffs = []
        for t in in_both:
            if counts_a[t] != counts_b[t]:
                count_diffs.append({
                    "tool": t,
                    f"session_{session_id_a}": counts_a[t],
                    f"session_{session_id_b}": counts_b[t]
                })

        shared = len(in_both)
        total = len(set_a | set_b)
        similarity = round(shared / total * 100, 1) if total else 100.0

        return {
            "session_a": {"id": session_id_a, "name": sa["name"], "tool_calls": len(seq_a)},
            "session_b": {"id": session_id_b, "name": sb["name"], "tool_calls": len(seq_b)},
            "similarity_pct": similarity,
            "only_in_a": only_in_a,
            "only_in_b": only_in_b,
            "call_count_differences": count_diffs,
            "shared_tools": in_both
        }


# ─────────────────────────────────────────────────────────────
#  MCP Server
# ─────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "session_start",
        "description": "Start a new named debug session. Sets it as the current active session for recording.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Session name, e.g. 'chrome heap uaf analysis'"},
                "target": {"type": "string", "description": "Binary or dump being analyzed, e.g. 'chrome.exe' or 'crash.dmp'"},
                "debugger": {"type": "string", "description": "Primary debugger: windbg | ida | x64dbg | mco"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "session_end",
        "description": "End the current (or specified) session and save notes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "integer", "description": "Session ID (omit to end current)"},
                "notes": {"type": "string", "description": "Summary notes about findings"}
            },
            "required": []
        }
    },
    {
        "name": "session_list",
        "description": "List recent debug sessions with stats (duration, tool calls, debugger).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max sessions to return (default 20)"}
            },
            "required": []
        }
    },
    {
        "name": "session_delete",
        "description": "Permanently delete a session and all its recorded events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "integer"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "session_record",
        "description": "Record a tool call into the current session. Call this after every MCP tool call you want to track.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
                "args": {"type": "object"},
                "result": {"type": "string"},
                "duration_ms": {"type": "integer"},
                "session_id": {"type": "integer", "description": "Omit to use current session"}
            },
            "required": ["tool_name", "result"]
        }
    },
    {
        "name": "session_search",
        "description": "Full-text search across all recorded tool outputs. Returns matching sessions with context snippets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term, e.g. 'use-after-free' or 'IsDebuggerPresent'"},
                "debugger": {"type": "string", "description": "Filter by debugger (optional)"},
                "date_from": {"type": "string", "description": "Filter from date, YYYY-MM-DD (optional)"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "session_replay",
        "description": "Return all tool calls from a session in chronological order with timestamps.",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "integer"}},
            "required": ["session_id"]
        }
    },
    {
        "name": "session_find_address",
        "description": "Find all sessions that mention a specific hex address in any tool output.",
        "inputSchema": {
            "type": "object",
            "properties": {"address": {"type": "string", "description": "Hex address, e.g. '0x7ff712340000'"}},
            "required": ["address"]
        }
    },
    {
        "name": "session_find_function",
        "description": "Find all sessions that mention a specific function name (e.g. 'NtUserSetWindowPos' or 'win32k!NtUser').",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"]
        }
    },
    {
        "name": "session_summary",
        "description": "Get an AI-readable summary of a session: top tools, key addresses found, critical findings.",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "integer"}},
            "required": ["session_id"]
        }
    },
    {
        "name": "session_export_markdown",
        "description": "Export a full Markdown report of a session — timeline of tool calls, key addresses, tools table. Ready to share.",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "integer"}},
            "required": ["session_id"]
        }
    },
    {
        "name": "session_stats",
        "description": "Global MCO stats: total sessions, total tool calls, most used tools, most analyzed targets.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "session_diff",
        "description": "Compare two sessions: which tools were used in one but not the other, call count differences, similarity %.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id_a": {"type": "integer"},
                "session_id_b": {"type": "integer"}
            },
            "required": ["session_id_a", "session_id_b"]
        }
    }
]


class MCPServer:
    def __init__(self):
        init_db()
        self.mgr = SessionManager()

    def _ok(self, data: Any) -> dict:
        return text_result(data)

    def _err(self, msg: str) -> dict:
        return text_error(msg)

    def handle(self, request: dict) -> dict | None:
        method = request.get("method")
        params = request.get("params", {})
        req_id = request.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "mco-sessions",
                        "version": "1.0.0",
                        "description": "MCO Session Intelligence — record, search, replay, export debug sessions"
                    }
                }
            }

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

        if method == "tools/call":
            tool = params.get("name")
            args = params.get("arguments", {})
            try:
                m = self.mgr
                if tool == "session_start":
                    r = m.session_start(args["name"], args.get("target", ""), args.get("debugger", ""))
                elif tool == "session_end":
                    r = m.session_end(args.get("session_id"), args.get("notes", ""))
                elif tool == "session_list":
                    r = m.session_list(args.get("limit", 20))
                elif tool == "session_delete":
                    r = m.session_delete(args["session_id"])
                elif tool == "session_record":
                    r = m.session_record(
                        args["tool_name"], args.get("args", {}),
                        args["result"], args.get("duration_ms", 0),
                        args.get("session_id")
                    )
                elif tool == "session_search":
                    r = m.session_search(args["query"], args.get("debugger", ""), args.get("date_from", ""))
                elif tool == "session_replay":
                    r = m.session_replay(args["session_id"])
                elif tool == "session_find_address":
                    r = m.session_find_address(args["address"])
                elif tool == "session_find_function":
                    r = m.session_find_function(args["name"])
                elif tool == "session_summary":
                    r = m.session_summary(args["session_id"])
                elif tool == "session_export_markdown":
                    r = m.session_export_markdown(args["session_id"])
                elif tool == "session_stats":
                    r = m.session_stats()
                elif tool == "session_diff":
                    r = m.session_diff(args["session_id_a"], args["session_id_b"])
                else:
                    return {"jsonrpc": "2.0", "id": req_id,
                            "result": self._err(f"Unknown tool: {tool}")}
                return {"jsonrpc": "2.0", "id": req_id, "result": self._ok(r)}
            except Exception as e:
                return {"jsonrpc": "2.0", "id": req_id, "result": self._err(str(e))}

        return {
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        }


def main():
    server = MCPServer()
    serve_stdio(server.handle)


if __name__ == "__main__":
    main()
