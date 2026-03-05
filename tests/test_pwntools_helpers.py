"""Unit tests for pwntools helper functions."""

import asyncio
import os
import pytest
from gdb_mcp.pwntools_helpers import (
    enumerate_processes,
    find_processes,
    wait_for_process,
    generate_gdbscript,
)


class TestEnumerateProcesses:
    """Test enumerate_processes function."""

    def test_returns_list(self):
        """enumerate_processes returns a list."""
        result = enumerate_processes()
        assert isinstance(result, list)

    def test_entries_have_required_keys(self):
        """Each entry has pid, comm, exe, cmdline keys."""
        result = enumerate_processes()
        assert len(result) > 0, "Should find at least one process"
        for proc in result[:5]:
            assert "pid" in proc
            assert "comm" in proc
            assert "exe" in proc
            assert "cmdline" in proc
            assert isinstance(proc["pid"], int)

    def test_finds_current_process(self):
        """Should find the current Python process."""
        my_pid = os.getpid()
        result = enumerate_processes()
        pids = [p["pid"] for p in result]
        assert my_pid in pids


class TestFindProcesses:
    """Test find_processes function."""

    def test_finds_python(self):
        """Should find at least one python process (ourselves)."""
        result = find_processes("python")
        assert len(result) > 0

    def test_empty_name_returns_empty(self):
        """Empty name returns empty list."""
        assert find_processes("") == []
        assert find_processes("   ") == []

    def test_no_match_returns_empty(self):
        """Non-matching name returns empty list."""
        result = find_processes("zzzz_nonexistent_process_name_12345")
        assert result == []

    def test_sorted_newest_first(self):
        """Results are sorted by PID descending."""
        result = find_processes("python")
        if len(result) > 1:
            pids = [p["pid"] for p in result]
            assert pids == sorted(pids, reverse=True)

    def test_case_insensitive(self):
        """Search is case-insensitive."""
        lower = find_processes("python")
        upper = find_processes("PYTHON")
        # Both should find our process
        lower_pids = {p["pid"] for p in lower}
        upper_pids = {p["pid"] for p in upper}
        assert lower_pids == upper_pids


class TestWaitForProcess:
    """Test wait_for_process async function."""

    def test_finds_existing_process(self):
        """Should immediately find an existing process."""
        result = asyncio.get_event_loop().run_until_complete(
            wait_for_process("python", timeout_sec=2.0)
        )
        assert result["status"] == "success"
        assert "match" in result
        assert result["match"]["pid"] > 0

    def test_timeout_on_nonexistent(self):
        """Should timeout on a nonexistent process."""
        result = asyncio.get_event_loop().run_until_complete(
            wait_for_process("zzzz_nonexistent_12345", timeout_sec=0.5, poll_interval_sec=0.1)
        )
        assert result["status"] == "error"
        assert "timeout" in result["message"].lower() or "not found" in result["message"].lower()


class TestGenerateGdbscript:
    """Test generate_gdbscript function."""

    def test_default_script(self):
        """Default script has pagination off, intel flavor, and continue."""
        script = generate_gdbscript()
        lines = script.split("\n")
        assert "set pagination off" in lines
        assert "set disassembly-flavor intel" in lines
        assert "c" in lines

    def test_with_breakpoints(self):
        """Breakpoints are included."""
        script = generate_gdbscript(breakpoints=["main", "*0x401234"])
        assert "b main" in script
        assert "b *0x401234" in script

    def test_with_commands(self):
        """Custom commands are included."""
        script = generate_gdbscript(commands=["x/20gx $rsp", "info registers"])
        assert "x/20gx $rsp" in script
        assert "info registers" in script

    def test_no_continue(self):
        """continue_after=False omits the 'c' at the end."""
        script = generate_gdbscript(continue_after=False)
        lines = script.split("\n")
        assert "c" not in lines

    def test_full_script(self):
        """Full script with breakpoints, commands, and continue."""
        script = generate_gdbscript(
            breakpoints=["main", "vuln"],
            commands=["x/4gx $rsp"],
            continue_after=True,
        )
        lines = script.split("\n")
        assert lines == [
            "set pagination off",
            "set disassembly-flavor intel",
            "b main",
            "b vuln",
            "x/4gx $rsp",
            "c",
        ]
