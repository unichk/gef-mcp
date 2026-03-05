"""MCP Server for GDB debugging interface."""

import asyncio
import json
import logging
import os
from typing import Any, Optional
from mcp.server import Server
from mcp.types import Tool, TextContent
from pydantic import BaseModel, Field
from .gdb_interface import GDBSession
from . import pwntools_helpers

# Set up logging - use GDB_MCP_LOG_LEVEL environment variable
log_level = os.environ.get("GDB_MCP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Global GDB session instance
gdb_session = GDBSession()

# Create MCP server instance
app = Server("gdb-mcp-server")


# Tool argument models
class StartSessionArgs(BaseModel):
    program: Optional[str] = Field(None, description="Path to executable to debug")
    args: Optional[list[str]] = Field(None, description="Command-line arguments for the program")
    init_commands: Optional[list[str]] = Field(
        None,
        description="GDB commands to run on startup (e.g., 'core-file /path/to/core', 'set sysroot /path')",
    )
    env: Optional[dict[str, str]] = Field(
        None,
        description="Environment variables to set for the debugged program (e.g., {'LD_LIBRARY_PATH': '/custom/libs'})",
    )
    gdb_path: Optional[str] = Field(
        None, description="Path to GDB executable (default: from GDB_PATH env var or 'gdb')"
    )
    working_dir: Optional[str] = Field(
        None,
        description=(
            "Working directory to use when starting GDB. "
            "Use this when debugging programs that need to be run from a specific directory, "
            "or when the program expects to find files (config, data, etc.) relative to its working directory. "
            "GDB will be started in this directory, then the original directory is restored. "
            "Example: If debugging a server that loads config from './config.json', set working_dir to the server's directory."
        ),
    )
    core: Optional[str] = Field(
        None,
        description=(
            "Path to core dump file for post-mortem debugging. "
            "When specified, GDB is started with --core flag which properly initializes symbol resolution. "
            "IMPORTANT: When using a sysroot with core dumps, set sysroot AFTER the core is loaded "
            "(either via this parameter or core-file command) for symbols to resolve correctly."
        ),
    )


class ExecuteCommandArgs(BaseModel):
    command: str = Field(..., description="GDB command to execute")


class GetBacktraceArgs(BaseModel):
    thread_id: Optional[int] = Field(None, description="Thread ID (None for current thread)")
    max_frames: int = Field(100, description="Maximum number of frames to retrieve")


class SetBreakpointArgs(BaseModel):
    location: str = Field(..., description="Breakpoint location (function, file:line, or *address)")
    condition: Optional[str] = Field(None, description="Conditional expression")
    temporary: bool = Field(False, description="Whether breakpoint is temporary")


class EvaluateExpressionArgs(BaseModel):
    expression: str = Field(..., description="C/C++ expression to evaluate")


class GetVariablesArgs(BaseModel):
    thread_id: Optional[int] = Field(None, description="Thread ID (None for current)")
    frame: int = Field(0, description="Frame number (0 is current)")


class ThreadSelectArgs(BaseModel):
    thread_id: int = Field(..., description="Thread ID to select")


class BreakpointNumberArgs(BaseModel):
    number: int = Field(..., description="Breakpoint number")


class FrameSelectArgs(BaseModel):
    frame_number: int = Field(..., description="Frame number (0 is current/innermost frame)")


class CallFunctionArgs(BaseModel):
    function_call: str = Field(
        ...,
        description="Function call expression (e.g., 'printf(\"hello\\n\")' or 'my_func(arg1, arg2)')",
    )


class ReadMemoryArgs(BaseModel):
    address: str = Field(
        ..., description="Memory address to read from (hex like '0x7fffffffe000' or expression like '$rsp')"
    )
    count: int = Field(64, description="Number of bytes to read (1-65536, default: 64)")


class TelescopeArgs(BaseModel):
    address: str = Field("$rsp", description="Start address or register (default: '$rsp')")
    count: int = Field(20, description="Number of entries to display (default: 20)")


class HeapInfoArgs(BaseModel):
    subcmd: str = Field(
        "chunks",
        description="Heap subcommand: 'chunks', 'bins', 'arenas', or 'chunk <addr>'",
    )


class SearchMemoryArgs(BaseModel):
    pattern: str = Field(..., description="Pattern to search for (string like 'FLAG{' or hex bytes)")
    start_address: Optional[str] = Field(None, description="Start address of search range")
    end_address: Optional[str] = Field(None, description="End address of search range")


class DisassembleArgs(BaseModel):
    location: str = Field(
        ..., description="Function name, address, or register (e.g., 'main', '0x401000', '$rip')"
    )
    count: Optional[int] = Field(
        None, description="Number of instructions (uses x/Ni format)"
    )


class DerefStringArgs(BaseModel):
    address: str = Field(..., description="Memory address to read string from (hex or expression)")


# Pwntools tool argument models
class AttachPidArgs(BaseModel):
    pid: int = Field(..., description="Process ID to attach to")
    binary: Optional[str] = Field(
        None, description="Path to executable for symbol resolution"
    )
    working_dir: Optional[str] = Field(
        None, description="Working directory for GDB"
    )


class FindProcessesArgs(BaseModel):
    name: str = Field(..., description="Process name substring to search for")
    limit: int = Field(20, description="Maximum number of results (1-200)")


class WaitForProcessArgs(BaseModel):
    name: str = Field(..., description="Process name substring to wait for")
    timeout_sec: float = Field(
        10.0, description="Maximum time to wait in seconds (0-300)"
    )
    poll_interval_sec: float = Field(
        0.2, description="Poll interval in seconds (0-5)"
    )


class AttachByNameArgs(BaseModel):
    name: str = Field(..., description="Process name substring to find and attach to")
    binary: Optional[str] = Field(
        None, description="Path to executable for symbol resolution"
    )
    working_dir: Optional[str] = Field(
        None, description="Working directory for GDB"
    )
    timeout_sec: float = Field(
        10.0, description="Maximum time to wait for process (0-300)"
    )


class PwntoolsAttachAndBreakArgs(BaseModel):
    name: str = Field(..., description="Process name substring to find and attach to")
    breakpoints: list[str] = Field(
        ..., description="List of breakpoint locations (function names, addresses like *0x401234, file:line)"
    )
    binary: Optional[str] = Field(
        None, description="Path to executable for symbol resolution"
    )
    working_dir: Optional[str] = Field(
        None, description="Working directory for GDB"
    )
    timeout_sec: float = Field(
        10.0, description="Maximum time to wait for process (0-300)"
    )
    follow_fork_mode: str = Field(
        "parent", description="Fork follow mode: 'parent' or 'child'"
    )
    detach_on_fork: bool = Field(
        True, description="Whether to detach from child on fork"
    )


class PwntoolsBootstrapArgs(BaseModel):
    breakpoints: Optional[list[str]] = Field(
        None, description="Optional list of breakpoint locations to set"
    )
    follow_fork_mode: str = Field(
        "parent", description="Fork follow mode: 'parent' or 'child'"
    )
    detach_on_fork: bool = Field(
        True, description="Whether to detach from child on fork"
    )


class GenerateGdbscriptArgs(BaseModel):
    breakpoints: Optional[list[str]] = Field(
        None, description="List of breakpoint locations"
    )
    commands: Optional[list[str]] = Field(
        None, description="Additional GDB commands to include in the script"
    )
    continue_after: bool = Field(
        True, description="Whether to add 'c' (continue) at the end of the script"
    )


# List available tools
@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available GDB debugging tools."""
    return [
        Tool(
            name="gdb_start_session",
            description=(
                "Start a new GDB debugging session. Can load an executable, core dump, "
                "or run custom initialization commands. "
                "Automatically detects and reports important warnings such as: "
                "missing debug symbols (not compiled with -g), file not found, or invalid executable. "
                "Check the 'warnings' field in the response for critical issues that may affect debugging. "
                "Available parameters: program (executable path), args (program arguments), "
                "core (core dump path - uses --core flag for proper symbol resolution), "
                "init_commands (GDB commands to run after loading), "
                "env (environment variables), gdb_path (GDB binary path), "
                "working_dir (directory to run program from). "
                "IMPORTANT for core dump debugging: Set 'sysroot' and 'solib-search-path' AFTER "
                "loading the core (either via 'core' parameter or 'core-file' init_command) "
                "for symbols to resolve correctly."
            ),
            inputSchema=StartSessionArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_execute_command",
            description=(
                "Execute a GDB command. Supports both CLI and MI commands. "
                "CLI commands (like 'info breakpoints', 'list', 'print x') are automatically "
                "handled and their output is formatted for readability. "
                "MI commands (starting with '-', like '-break-list', '-exec-run') return "
                "structured data. "
                "NOTE: For calling functions in the target process, prefer using the dedicated "
                "gdb_call_function tool instead of 'call' command, as it provides better "
                "structured output and can be separately permissioned. "
                "Common examples: 'info breakpoints', 'info threads', 'run', 'print variable', "
                "'list main', 'disassemble func'."
            ),
            inputSchema=ExecuteCommandArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_get_status",
            description="Get the current status of the GDB session.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_get_threads",
            description=(
                "Get information about all threads in the debugged process, including "
                "thread IDs, states, and the current thread."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_select_thread",
            description=(
                "Select a specific thread to make it the current thread. "
                "After selecting a thread, subsequent commands like gdb_get_backtrace, "
                "gdb_get_variables, and gdb_evaluate_expression will operate on this thread. "
                "Use gdb_get_threads to see available thread IDs."
            ),
            inputSchema=ThreadSelectArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_get_backtrace",
            description=(
                "Get the stack backtrace for a specific thread or the current thread. "
                "Shows function calls, file locations, and line numbers."
            ),
            inputSchema=GetBacktraceArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_select_frame",
            description=(
                "Select a specific stack frame to make it the current frame. "
                "Frame 0 is the innermost (current) frame, higher numbers are outer frames. "
                "After selecting a frame, commands like gdb_get_variables and gdb_evaluate_expression "
                "will operate in the context of that frame. "
                "Use gdb_get_backtrace to see available frames and their numbers."
            ),
            inputSchema=FrameSelectArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_get_frame_info",
            description=(
                "Get information about the current stack frame. "
                "Returns details about the currently selected frame including function name, "
                "file location, line number, and address. "
                "Use gdb_select_frame to change the current frame first if needed."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="gdb_set_breakpoint",
            description=(
                "Set a breakpoint at a function, file:line, or address. "
                "Supports conditional breakpoints and temporary breakpoints. "
                "Returns breakpoint details including number, address, and location. "
                "Use gdb_list_breakpoints to verify breakpoints were set correctly."
            ),
            inputSchema=SetBreakpointArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_list_breakpoints",
            description=(
                "List all breakpoints as structured data with detailed information. "
                "Returns an array of breakpoint objects, each containing: number, type, "
                "enabled status, address, function name, source file, line number, and hit count. "
                "Use this to verify breakpoints were set correctly, check which have been hit "
                "(times field), and inspect their exact locations. "
                "Much easier to filter and analyze than text output."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_delete_breakpoint",
            description=(
                "Delete a breakpoint by its number. "
                "Use gdb_list_breakpoints to see breakpoint numbers. "
                "Once deleted, the breakpoint cannot be recovered."
            ),
            inputSchema=BreakpointNumberArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_enable_breakpoint",
            description=(
                "Enable a previously disabled breakpoint by its number. "
                "Enabled breakpoints will pause execution when hit."
            ),
            inputSchema=BreakpointNumberArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_disable_breakpoint",
            description=(
                "Disable a breakpoint by its number without deleting it. "
                "Disabled breakpoints are not hit but remain in the breakpoint list. "
                "Use gdb_enable_breakpoint to re-enable it later."
            ),
            inputSchema=BreakpointNumberArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_continue",
            description=(
                "Continue execution of the program until next breakpoint or completion. "
                "IMPORTANT: Only use this when the program is PAUSED (e.g., at a breakpoint). "
                "If the program hasn't been started yet, use gdb_execute_command with 'run' instead. "
                "If the program is already running, this will fail - use gdb_interrupt to pause it first."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_step",
            description=(
                "Step into the next instruction (enters function calls). "
                "IMPORTANT: Only works when program is PAUSED at a specific location. "
                "Use this for single-stepping through code to debug line-by-line."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_next",
            description=(
                "Step over to the next line (doesn't enter function calls). "
                "IMPORTANT: Only works when program is PAUSED at a specific location. "
                "Use this to step over function calls without entering them."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_interrupt",
            description=(
                "Interrupt (pause) a running program. Use this when: "
                "1) The program is running and hasn't hit a breakpoint, "
                "2) You want to pause execution to inspect state or set breakpoints, "
                "3) The program appears stuck or you want to see where it is. "
                "After interrupting, you can use other commands like gdb_get_backtrace, "
                "gdb_get_variables, or gdb_continue."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_evaluate_expression",
            description=(
                "Evaluate a C/C++ expression in the current context and return its value. "
                "Can access variables, dereference pointers, call functions, etc."
            ),
            inputSchema=EvaluateExpressionArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_get_variables",
            description="Get local variables for a specific stack frame in a thread.",
            inputSchema=GetVariablesArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_get_registers",
            description="Get CPU register values for the current frame.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_stop_session",
            description="Stop the current GDB session and clean up resources.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="gdb_call_function",
            description=(
                "Call a function in the target process. "
                "WARNING: This is a privileged operation that executes code in the debugged program. "
                "It can call any function accessible in the current context, including: "
                "- Standard library functions: printf, malloc, free, etc. "
                "- Program functions: any function defined in the program "
                "- System calls via wrappers "
                "The function executes with full privileges of the debugged process. "
                "Use with caution as it may have side effects and modify program state. "
                "Examples: 'printf(\"debug: x=%d\\n\", x)', 'my_cleanup_func()', 'strlen(str)'"
            ),
            inputSchema=CallFunctionArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_vmmap",
            description=(
                "Get virtual memory map of the debugged process. "
                "Returns structured information about all memory regions including "
                "their addresses, sizes, permissions, and associated files/regions. "
                "Useful for understanding process memory layout, locating code sections, "
                "heap/stack regions, and library mappings."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        # CTF tools
        Tool(
            name="gdb_checksec",
            description=(
                "Get security properties of the loaded binary (NX, PIE, canary, RELRO, etc.) "
                "using GEF's checksec command. Returns structured property data."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="gdb_telescope",
            description=(
                "Smart pointer dereference using GEF's telescope command. Shows a chain of "
                "pointer dereferences at each address, revealing stack contents, heap pointers, "
                "strings, and code references. Default: telescope from $rsp."
            ),
            inputSchema=TelescopeArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_heap_info",
            description=(
                "Get heap information using GEF's heap commands. Subcommands: "
                "'chunks' (list all chunks), 'bins' (show bin lists), "
                "'arenas' (show arena info), 'chunk <addr>' (inspect specific chunk)."
            ),
            inputSchema=HeapInfoArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_got",
            description=(
                "Show the Global Offset Table (GOT) entries using GEF's got command. "
                "Useful for identifying resolved libc function addresses for leak exploitation."
            ),
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="gdb_search_memory",
            description=(
                "Search memory for a byte pattern or string across all mapped regions. "
                "If start_address and end_address are provided, searches only that range. "
                "Useful for finding flags, gadgets, or specific byte sequences."
            ),
            inputSchema=SearchMemoryArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_disassemble",
            description=(
                "Disassemble code at a function name, address, or register. "
                "Optionally specify count for number of instructions. "
                "Without count, disassembles the entire function."
            ),
            inputSchema=DisassembleArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_deref_string",
            description=(
                "Read a null-terminated string at a memory address. "
                "Useful for inspecting string buffers, format strings, or flag values."
            ),
            inputSchema=DerefStringArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_read_memory",
            description=(
                "Read memory bytes from the debugged process at a given address. "
                "Returns structured hex data. Address can be a hex value like '0x7fffffffe000' "
                "or a register expression like '$rsp'. Count specifies bytes to read (1-65536)."
            ),
            inputSchema=ReadMemoryArgs.model_json_schema(),
        ),
        # Pwntools tools
        Tool(
            name="gdb_attach_pid",
            description=(
                "Attach GDB to a running process by PID. Optionally provide a binary "
                "path for symbol resolution. This stops any existing GDB session first, "
                "then attaches to the specified PID. After attach, the process is paused "
                "and ready for breakpoints/inspection."
            ),
            inputSchema=AttachPidArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_find_processes",
            description=(
                "Find running processes by name substring match. Searches across "
                "process comm, exe path, and full command line. Results sorted newest-first. "
                "Useful for finding pwntools-spawned processes before attaching."
            ),
            inputSchema=FindProcessesArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_wait_for_process",
            description=(
                "Wait for a process matching name to appear. Polls periodically until "
                "a match is found or timeout is reached. Useful when pwntools spawns "
                "the target and you need to wait for it to start."
            ),
            inputSchema=WaitForProcessArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_attach_by_name",
            description=(
                "Wait for a process by name, then attach GDB to it. Combines "
                "wait_for_process + attach_pid in one call. The newest matching "
                "process (highest PID) is chosen."
            ),
            inputSchema=AttachByNameArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_pwntools_attach_and_break",
            description=(
                "All-in-one pwntools attach: wait for process, attach GDB, apply "
                "exploit-friendly settings (fork mode, pagination off, intel disasm), "
                "and set breakpoints. This is the recommended tool for the typical "
                "pwntools workflow: spawn process in pwntools, then call this tool "
                "to attach and set up breakpoints in one step."
            ),
            inputSchema=PwntoolsAttachAndBreakArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_pwntools_bootstrap",
            description=(
                "Apply exploit-friendly GDB settings on an already-attached session: "
                "set fork follow mode, detach-on-fork, intel disassembly, pagination off, "
                "and optionally set initial breakpoints. Use this after gdb_attach_pid "
                "or gdb_start_session if you didn't use gdb_pwntools_attach_and_break."
            ),
            inputSchema=PwntoolsBootstrapArgs.model_json_schema(),
        ),
        Tool(
            name="gdb_generate_pwntools_gdbscript",
            description=(
                "Generate a pwntools gdb.attach() gdbscript string. Returns a script "
                "with pagination off, intel disasm flavor, breakpoints, custom commands, "
                "and optional continue. Use the output in pwntools: "
                "gdb.attach(p, gdbscript=result['gdbscript'])"
            ),
            inputSchema=GenerateGdbscriptArgs.model_json_schema(),
        ),
    ]


# Tool implementations
@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    """Handle tool calls from the MCP client."""

    try:
        if name == "gdb_start_session":
            args = StartSessionArgs(**arguments)
            result = gdb_session.start(
                program=args.program,
                args=args.args,
                init_commands=args.init_commands,
                env=args.env,
                gdb_path=args.gdb_path,
                working_dir=args.working_dir,
                core=args.core,
            )

        elif name == "gdb_execute_command":
            exec_args: ExecuteCommandArgs = ExecuteCommandArgs(**arguments)
            result = gdb_session.execute_command(command=exec_args.command)

        elif name == "gdb_get_status":
            result = gdb_session.get_status()

        elif name == "gdb_get_threads":
            result = gdb_session.get_threads()

        elif name == "gdb_select_thread":
            thread_args: ThreadSelectArgs = ThreadSelectArgs(**arguments)
            result = gdb_session.select_thread(thread_id=thread_args.thread_id)

        elif name == "gdb_get_backtrace":
            backtrace_args: GetBacktraceArgs = GetBacktraceArgs(**arguments)
            result = gdb_session.get_backtrace(
                thread_id=backtrace_args.thread_id, max_frames=backtrace_args.max_frames
            )

        elif name == "gdb_select_frame":
            frame_args: FrameSelectArgs = FrameSelectArgs(**arguments)
            result = gdb_session.select_frame(frame_number=frame_args.frame_number)

        elif name == "gdb_get_frame_info":
            result = gdb_session.get_frame_info()

        elif name == "gdb_set_breakpoint":
            bp_args: SetBreakpointArgs = SetBreakpointArgs(**arguments)
            result = gdb_session.set_breakpoint(
                location=bp_args.location, condition=bp_args.condition, temporary=bp_args.temporary
            )

        elif name == "gdb_list_breakpoints":
            result = gdb_session.list_breakpoints()

        elif name == "gdb_delete_breakpoint":
            del_bp_args: BreakpointNumberArgs = BreakpointNumberArgs(**arguments)
            result = gdb_session.delete_breakpoint(number=del_bp_args.number)

        elif name == "gdb_enable_breakpoint":
            en_bp_args: BreakpointNumberArgs = BreakpointNumberArgs(**arguments)
            result = gdb_session.enable_breakpoint(number=en_bp_args.number)

        elif name == "gdb_disable_breakpoint":
            dis_bp_args: BreakpointNumberArgs = BreakpointNumberArgs(**arguments)
            result = gdb_session.disable_breakpoint(number=dis_bp_args.number)

        elif name == "gdb_continue":
            result = gdb_session.continue_execution()

        elif name == "gdb_step":
            result = gdb_session.step()

        elif name == "gdb_next":
            result = gdb_session.next()

        elif name == "gdb_interrupt":
            result = gdb_session.interrupt()

        elif name == "gdb_evaluate_expression":
            eval_args: EvaluateExpressionArgs = EvaluateExpressionArgs(**arguments)
            result = gdb_session.evaluate_expression(eval_args.expression)

        elif name == "gdb_get_variables":
            var_args: GetVariablesArgs = GetVariablesArgs(**arguments)
            result = gdb_session.get_variables(thread_id=var_args.thread_id, frame=var_args.frame)

        elif name == "gdb_get_registers":
            result = gdb_session.get_registers()

        elif name == "gdb_stop_session":
            result = gdb_session.stop()

        elif name == "gdb_call_function":
            call_args: CallFunctionArgs = CallFunctionArgs(**arguments)
            result = gdb_session.call_function(function_call=call_args.function_call)

        elif name == "gdb_vmmap":
            result = gdb_session.get_vmmap()

        elif name == "gdb_checksec":
            result = gdb_session.checksec()

        elif name == "gdb_telescope":
            tel_args = TelescopeArgs(**arguments)
            result = gdb_session.telescope(address=tel_args.address, count=tel_args.count)

        elif name == "gdb_heap_info":
            heap_args = HeapInfoArgs(**arguments)
            result = gdb_session.heap_info(subcmd=heap_args.subcmd)

        elif name == "gdb_got":
            result = gdb_session.got()

        elif name == "gdb_search_memory":
            search_args = SearchMemoryArgs(**arguments)
            result = gdb_session.search_memory(
                pattern=search_args.pattern,
                start_address=search_args.start_address,
                end_address=search_args.end_address,
            )

        elif name == "gdb_disassemble":
            dis_args = DisassembleArgs(**arguments)
            result = gdb_session.disassemble(location=dis_args.location, count=dis_args.count)

        elif name == "gdb_deref_string":
            ds_args = DerefStringArgs(**arguments)
            result = gdb_session.deref_string(address=ds_args.address)

        elif name == "gdb_read_memory":
            mem_args = ReadMemoryArgs(**arguments)
            result = gdb_session.read_memory(address=mem_args.address, count=mem_args.count)

        # Pwntools tools
        elif name == "gdb_attach_pid":
            attach_args = AttachPidArgs(**arguments)
            result = gdb_session.attach_to_pid(
                pid=attach_args.pid,
                binary=attach_args.binary,
                working_dir=attach_args.working_dir,
            )

        elif name == "gdb_find_processes":
            find_args = FindProcessesArgs(**arguments)
            if find_args.limit < 1 or find_args.limit > 200:
                result = {"status": "error", "message": "limit must be between 1 and 200"}
            else:
                matches = pwntools_helpers.find_processes(find_args.name)[:find_args.limit]
                result = {"status": "success", "name": find_args.name, "matches": matches}

        elif name == "gdb_wait_for_process":
            wait_args = WaitForProcessArgs(**arguments)
            if wait_args.timeout_sec <= 0 or wait_args.timeout_sec > 300:
                result = {"status": "error", "message": "timeout_sec must be between 0 and 300"}
            elif wait_args.poll_interval_sec <= 0 or wait_args.poll_interval_sec > 5:
                result = {"status": "error", "message": "poll_interval_sec must be between 0 and 5"}
            else:
                result = await pwntools_helpers.wait_for_process(
                    name=wait_args.name,
                    timeout_sec=wait_args.timeout_sec,
                    poll_interval_sec=wait_args.poll_interval_sec,
                )

        elif name == "gdb_attach_by_name":
            abn_args = AttachByNameArgs(**arguments)
            wait_result = await pwntools_helpers.wait_for_process(
                name=abn_args.name, timeout_sec=abn_args.timeout_sec
            )
            if wait_result.get("status") == "error":
                result = wait_result
            else:
                pid = int(wait_result["match"]["pid"])
                result = gdb_session.attach_to_pid(
                    pid=pid, binary=abn_args.binary, working_dir=abn_args.working_dir
                )
                if result.get("status") == "success":
                    result["matched_process"] = wait_result["match"]

        elif name == "gdb_pwntools_attach_and_break":
            pab_args = PwntoolsAttachAndBreakArgs(**arguments)
            # Step 1: Wait for and attach to the process
            wait_result = await pwntools_helpers.wait_for_process(
                name=pab_args.name, timeout_sec=pab_args.timeout_sec
            )
            if wait_result.get("status") == "error":
                result = wait_result
            else:
                pid = int(wait_result["match"]["pid"])
                attach_result = gdb_session.attach_to_pid(
                    pid=pid, binary=pab_args.binary, working_dir=pab_args.working_dir
                )
                if attach_result.get("status") == "error":
                    result = attach_result
                else:
                    # Step 2: Bootstrap (apply exploit settings + set breakpoints)
                    bootstrap_results = []
                    # Apply runtime options
                    fork_mode = pab_args.follow_fork_mode
                    detach = "on" if pab_args.detach_on_fork else "off"
                    gdb_session.execute_command(f"set follow-fork-mode {fork_mode}")
                    gdb_session.execute_command(f"set detach-on-fork {detach}")
                    gdb_session.execute_command("set disassembly-flavor intel")
                    gdb_session.execute_command("set pagination off")
                    gdb_session.execute_command("set print asm-demangle on")
                    gdb_session.execute_command("set disassemble-next-line on")
                    # Set breakpoints
                    for bp in pab_args.breakpoints:
                        bp_result = gdb_session.set_breakpoint(location=bp)
                        bootstrap_results.append(bp_result)
                    result = {
                        "status": "success",
                        "message": f"Attached to PID {pid} and set {len(pab_args.breakpoints)} breakpoints",
                        "pid": pid,
                        "binary": pab_args.binary,
                        "matched_process": wait_result["match"],
                        "breakpoints": bootstrap_results,
                    }

        elif name == "gdb_pwntools_bootstrap":
            boot_args = PwntoolsBootstrapArgs(**arguments)
            if not gdb_session.controller:
                result = {"status": "error", "message": "No active GDB session to bootstrap"}
            else:
                fork_mode = boot_args.follow_fork_mode
                detach = "on" if boot_args.detach_on_fork else "off"
                gdb_session.execute_command(f"set follow-fork-mode {fork_mode}")
                gdb_session.execute_command(f"set detach-on-fork {detach}")
                gdb_session.execute_command("set disassembly-flavor intel")
                gdb_session.execute_command("set pagination off")
                gdb_session.execute_command("set print asm-demangle on")
                gdb_session.execute_command("set disassemble-next-line on")
                bp_results = []
                for bp in boot_args.breakpoints or []:
                    bp_result = gdb_session.set_breakpoint(location=bp)
                    bp_results.append(bp_result)
                result = {
                    "status": "success",
                    "message": "Bootstrap complete",
                    "breakpoints": bp_results,
                }

        elif name == "gdb_generate_pwntools_gdbscript":
            gs_args = GenerateGdbscriptArgs(**arguments)
            script = pwntools_helpers.generate_gdbscript(
                breakpoints=gs_args.breakpoints,
                commands=gs_args.commands,
                continue_after=gs_args.continue_after,
            )
            result = {"status": "success", "gdbscript": script}

        else:
            result = {"status": "error", "message": f"Unknown tool: {name}"}

        # Format result as text
        result_text = json.dumps(result, indent=2)

        return [TextContent(type="text", text=result_text)]

    except Exception as e:
        logger.error(f"Error executing tool {name}: {e}", exc_info=True)
        error_result = {"status": "error", "message": str(e), "tool": name}
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def main():
    """Main async entry point for the MCP server."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        logger.info("GDB MCP Server starting...")
        await app.run(read_stream, write_stream, app.create_initialization_options())


def run_server():
    """Synchronous entry point for the MCP server (for script entry point)."""
    asyncio.run(main())


if __name__ == "__main__":
    run_server()
