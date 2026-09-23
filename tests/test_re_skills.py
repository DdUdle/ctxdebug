"""Tests for the small x64dbg RE search skills."""

import pytest

from agent.skills.analysis import skill_find_module, skill_find_string


class FakeBridge:
    async def get_modules(self):
        return [
            {"name": "target.exe", "path": r"C:\\ctf\\target.exe", "base": 0x140000000, "size": 0x2000},
            {"name": "kernel32.dll", "path": r"C:\\Windows\\System32\\kernel32.dll", "base": 0x7FF800000000, "size": 0x10000},
        ]

    async def search_strings(self, min_length=4):
        assert min_length == 4
        return [
            {"address": 0x140001000, "text": "CTF{demo_flag}"},
            {"address": 0x140001100, "text": "Normal message"},
        ]


@pytest.mark.asyncio
async def test_find_module_by_name():
    result = await skill_find_module(FakeBridge(), None, {"query": "KERNEL32"})

    assert result.success
    assert result.data[0]["name"] == "kernel32.dll"


@pytest.mark.asyncio
async def test_find_module_resolves_rva():
    result = await skill_find_module(FakeBridge(), None, {"query": "0x140001234"})

    assert result.success
    assert result.data[0]["name"] == "target.exe"
    assert result.data[0]["rva"] == 0x1234


@pytest.mark.asyncio
async def test_find_string_is_case_insensitive_and_limited():
    result = await skill_find_string(
        FakeBridge(), None, {"query": "FLAG", "limit": 1}
    )

    assert result.success
    assert len(result.data) == 1
    assert result.data[0]["address"] == 0x140001000


@pytest.mark.asyncio
async def test_find_skills_require_query():
    module_result = await skill_find_module(FakeBridge(), None, {})
    string_result = await skill_find_string(FakeBridge(), None, {"query": " "})

    assert not module_result.success
    assert not string_result.success
