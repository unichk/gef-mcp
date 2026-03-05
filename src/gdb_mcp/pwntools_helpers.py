"""Pwntools-oriented helper functions for process discovery and gdbscript generation."""

import asyncio
import os
import time
from typing import Any, Optional


def enumerate_processes() -> list[dict[str, Any]]:
    """
    Scan /proc for all running processes.

    Returns:
        List of dicts with keys: pid, comm, exe, cmdline
    """
    processes: list[dict[str, Any]] = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        proc_dir = os.path.join("/proc", entry)
        cmdline_path = os.path.join(proc_dir, "cmdline")
        comm_path = os.path.join(proc_dir, "comm")
        exe_path = os.path.join(proc_dir, "exe")
        try:
            cmdline_raw = open(cmdline_path, "rb").read()
            cmdline_parts = [p.decode(errors="replace") for p in cmdline_raw.split(b"\x00") if p]
            cmdline = " ".join(cmdline_parts)
            if not cmdline:
                cmdline = (
                    open(comm_path, "r", encoding="utf-8", errors="replace").read().strip()
                )
            exe = os.readlink(exe_path)
            comm = os.path.basename(exe)
        except Exception:
            continue
        processes.append({"pid": pid, "comm": comm, "exe": exe, "cmdline": cmdline})
    return processes


def find_processes(name: str) -> list[dict[str, Any]]:
    """
    Find processes whose comm, exe, or cmdline contains the given substring (case-insensitive).

    Results are sorted newest-first (highest PID first).

    Args:
        name: Substring to search for

    Returns:
        List of matching process dicts
    """
    query = name.strip().lower()
    if not query:
        return []
    matched = []
    for proc in enumerate_processes():
        haystack = f"{proc['comm']} {proc['exe']} {proc['cmdline']}".lower()
        if query in haystack:
            matched.append(proc)
    matched.sort(key=lambda x: x["pid"], reverse=True)
    return matched


async def wait_for_process(
    name: str, timeout_sec: float = 10.0, poll_interval_sec: float = 0.2
) -> dict[str, Any]:
    """
    Wait for a process matching name to appear.

    Useful when pwntools spawns the target and the MCP server needs to find it.

    Args:
        name: Process name substring to search for
        timeout_sec: Maximum time to wait (0 < timeout <= 300)
        poll_interval_sec: Poll interval (0 < interval <= 5)

    Returns:
        Dict with status and match info, or error on timeout
    """
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        matches = find_processes(name)
        if matches:
            return {
                "status": "success",
                "name": name,
                "match": matches[0],
                "matches": matches[:10],
            }
        await asyncio.sleep(poll_interval_sec)
    return {
        "status": "error",
        "message": f"No process matching '{name}' found within {timeout_sec}s timeout",
    }


def generate_gdbscript(
    breakpoints: Optional[list[str]] = None,
    commands: Optional[list[str]] = None,
    continue_after: bool = True,
) -> str:
    """
    Generate a gdbscript suitable for pwntools gdb.attach().

    Args:
        breakpoints: List of breakpoint locations (function names, addresses, file:line)
        commands: Additional GDB commands to include
        continue_after: Whether to add 'c' (continue) at the end

    Returns:
        Multi-line gdbscript string
    """
    lines = ["set pagination off", "set disassembly-flavor intel"]
    for bp in breakpoints or []:
        lines.append(f"b {bp}")
    for cmd in commands or []:
        lines.append(cmd)
    if continue_after:
        lines.append("c")
    return "\n".join(lines)
