# GDB MCP Server - Tools Reference

This document provides detailed documentation for all available tools in the GDB MCP Server.

## Session Management

### `gdb_start_session`
Start a new GDB debugging session.

**Parameters:**
- `program` (optional): Path to executable to debug
- `args` (optional): Command-line arguments for the program
- `core` (optional): Path to core dump file (uses --core flag for proper symbol resolution)
- `init_commands` (optional): List of GDB commands to run on startup
- `env` (optional): Environment variables to set for the debugged program (dictionary of name-value pairs)
- `gdb_path` (optional): Path to GDB executable (default: "gdb")
- `working_dir` (optional): Working directory to use when starting GDB

**Returns:**
- `status`: "success" or "error"
- `message`: Status message
- `program` (optional): Program path if specified
- `core` (optional): Core dump path if specified
- `startup_output` (optional): GDB's initial output when loading the program
- `warnings` (optional): Array of critical warnings detected, such as:
  - "No debugging symbols found - program was not compiled with -g"
  - "File is not an executable"
  - "Program file not found"
- `env_output` (optional): Output from setting environment variables if env was provided
- `init_output` (optional): Output from init_commands if provided

**Important:** Always check the `warnings` field! Missing debug symbols will prevent breakpoints from working and variable inspection from showing useful information.

**Core Dump Debugging:**

When debugging core dumps with a sysroot, the order of operations matters for proper symbol resolution. Set `sysroot` and `solib-search-path` **AFTER** loading the core:

```json
{
  "program": "/path/to/executable",
  "core": "/path/to/core.dump",
  "init_commands": [
    "set sysroot /path/to/sysroot",
    "set solib-search-path /path/to/libs"
  ]
}
```

If using `core-file` in init_commands instead of the `core` parameter, ensure it comes before sysroot:
```python
[
    "core-file /path/to/core.dump",
    "set sysroot /path/to/sysroot",
    "set solib-search-path /path/to/libs"
]
```

**Example with custom GDB path:**
```json
{
  "program": "/path/to/myprogram",
  "gdb_path": "/usr/local/bin/gdb-custom"
}
```

Use `gdb_path` when you need to use a specific GDB version or when GDB is not in your PATH.

**Example with environment variables:**
```json
{
  "program": "/path/to/myprogram",
  "env": {
    "LD_LIBRARY_PATH": "/custom/libs:/opt/libs",
    "DEBUG_MODE": "1",
    "LOG_LEVEL": "verbose"
  }
}
```

Environment variables are set for the debugged program before execution. This is useful for:
- Setting library search paths (LD_LIBRARY_PATH, DYLD_LIBRARY_PATH)
- Configuring application behavior (DEBUG_MODE, LOG_LEVEL, etc.)
- Testing with different environment configurations

**Example Output:**
```json
{
  "status": "success",
  "message": "GDB session started successfully",
  "program": "/path/to/myprogram",
  "startup_output": "Reading symbols from /path/to/myprogram...\nReading symbols from /usr/lib/libc.so.6...\n(gdb)"
}
```

### `gdb_execute_command`
Execute a GDB command. Supports both CLI and MI commands.

**Parameters:**
- `command`: GDB command to execute (CLI or MI format)
- `timeout_sec`: Timeout in seconds (default: 30)

**NOTE:** For calling functions in the target process, prefer using the dedicated
`gdb_call_function` tool instead of the 'call' command, as it provides better
structured output and can be separately permissioned.

**Automatically handles two types of commands:**

1. **CLI Commands** (traditional GDB commands):
   - Examples: `info breakpoints`, `list`, `print x`, `run`, `backtrace`
   - Output is formatted as readable text
   - These are the commands you'd type in interactive GDB

2. **MI Commands** (Machine Interface commands, start with `-`):
   - Examples: `-break-list`, `-exec-run`, `-data-evaluate-expression`
   - Return structured data
   - More precise but less human-readable

**Common CLI commands:**
- `info breakpoints` - List all breakpoints
- `info threads` - List all threads
- `run` - Start the program
- `print variable` - Print a variable's value
- `backtrace` - Show call stack
- `list` - Show source code
- `disassemble` - Show assembly code

**Example Output (CLI command):**
```json
{
  "status": "success",
  "output": "Num     Type           Disp Enb Address            What\n1       breakpoint     keep y   0x0000555555555189 in main at main.cpp:10"
}
```

**Example Output (MI command):**
```json
{
  "status": "success",
  "output": {
    "breakpoints": [
      {
        "number": "1",
        "type": "breakpoint",
        "disp": "keep",
        "enabled": "y",
        "addr": "0x0000555555555189",
        "func": "main",
        "file": "main.cpp",
        "line": "10"
      }
    ]
  }
}
```

### `gdb_call_function`
Call a function in the target process.

**WARNING:** This is a privileged operation that executes code in the debugged program. Use with caution as it may have side effects.

**Parameters:**
- `function_call`: Function call expression (e.g., `printf("hello\n")` or `my_func(arg1, arg2)`)
- `timeout_sec`: Timeout in seconds (default: 30)

**Returns:**
- `status`: "success" or "error"
- `function_call`: The function call expression that was executed
- `result`: The return value or output from the function call

**Use this for:**
- Calling standard library functions: `printf("debug: x=%d\n", x)`, `strlen(str)`
- Calling program functions: `my_cleanup_func()`, `reset_state()`
- Inspecting complex data structures via helper functions

**Examples:**
```json
{"function_call": "printf(\"value: %d\\n\", x)"}
{"function_call": "strlen(buffer)"}
{"function_call": "validate_state()"}
```

**Note:** This dedicated tool enables MCP clients to implement separate permission controls for function calling, which executes code in the target process with the target's privileges.

**Example Output:**
```json
{
  "status": "success",
  "function_call": "printf(\"value: %d\\n\", x)",
  "result": "value: 42\n"
}
```

### `gdb_get_status`
Get the current status of the GDB session.

**Example Output:**
```json
{
  "status": "success",
  "message": "GDB session is active and running"
}
```

### `gdb_stop_session`
Stop the current GDB session.

**Example Output:**
```json
{
  "status": "success",
  "message": "GDB session stopped successfully"
}
```

## Thread Inspection

### `gdb_get_threads`
Get information about all threads in the debugged process.

**Returns:**
- List of threads with IDs and states
- Current thread ID
- Thread count

**Example Output:**
```json
{
  "status": "success",
  "threads": [
    {
      "id": "1",
      "state": "running",
      "name": "main_thread",
      "frame": {
        "addr": "0x00007ffff7a10d60",
        "func": "__select",
        "file": "select.c",
        "fullname": "/build/glibc-linux/select.c",
        "line": "28"
      }
    },
    {
      "id": "2",
      "state": "blocked",
      "name": "worker_thread",
      "frame": {
        "addr": "0x00007ffff7a10eac",
        "func": "__pselect50",
        "file": "pselect.c",
        "fullname": "/build/glibc-linux/pselect.c",
        "line": "48"
      }
    }
  ],
  "current_thread": "1",
  "count": 2
}
```

### `gdb_get_backtrace`
Get stack backtrace for a thread.

**Parameters:**
- `thread_id` (optional): Thread ID (None for current thread)
- `max_frames`: Maximum frames to retrieve (default: 100)

**Example Output:**
```json
{
  "status": "success",
  "frames": [
    {
      "level": "0",
      "addr": "0x0000555555555189",
      "func": "main",
      "file": "main.cpp",
      "fullname": "/home/user/project/main.cpp",
      "line": "15"
    },
    {
      "level": "1",
      "addr": "0x00007ffff7a3d505",
      "func": "__libc_start_main",
      "file": "libc-start.c",
      "fullname": "/build/glibc-linux/libc-start.c",
      "line": "342"
    },
    {
      "level": "2",
      "addr": "0x0000555555554ae9",
      "func": "_start",
      "file": "??",
      "fullname": "??",
      "line": "0"
    }
  ],
  "count": 3
}
```

## Breakpoints and Execution Control

### `gdb_set_breakpoint`
Set a breakpoint at a location.

**Parameters:**
- `location`: Function name, file:line, or *address
- `condition` (optional): Conditional expression
- `temporary`: Whether breakpoint is temporary (default: false)

**Examples:**
- `location: "main"` - Break at main function
- `location: "foo.c:42"` - Break at line 42 of foo.c
- `location: "*0x12345678"` - Break at memory address
- `condition: "x > 10"` - Only break when x > 10

**Example Output:**
```json
{
  "status": "success",
  "number": "1",
  "type": "breakpoint",
  "enabled": "y",
  "addr": "0x0000555555555189",
  "func": "main",
  "file": "main.cpp",
  "fullname": "/home/user/project/main.cpp",
  "line": "15",
  "times": "0",
  "original-location": "main.cpp:15"
}
```

### `gdb_list_breakpoints`
List all breakpoints with structured data.

**Returns:**
- `status`: "success" or "error"
- `breakpoints`: Array of breakpoint objects
- `count`: Total number of breakpoints

**Each breakpoint object contains:**
- `number`: Breakpoint number (string)
- `type`: "breakpoint", "watchpoint", etc.
- `enabled`: "y" or "n"
- `addr`: Memory address (e.g., "0x0000000000401234")
- `func`: Function name (if available)
- `file`: Source file name (if available)
- `fullname`: Full path to source file (if available)
- `line`: Line number (if available)
- `times`: Number of times this breakpoint has been hit (string)
- `original-location`: Original location string used to set the breakpoint

**Example output:**
```json
{
  "status": "success",
  "breakpoints": [
    {
      "number": "1",
      "type": "breakpoint",
      "enabled": "y",
      "addr": "0x0000000000016cd5",
      "func": "HeapColorStrategy::operator()",
      "file": "color_strategy.hpp",
      "fullname": "/home/user/project/src/color_strategy.hpp",
      "line": "119",
      "times": "3",
      "original-location": "color_strategy.hpp:119"
    }
  ],
  "count": 1
}
```

**Use this to:**
- Verify breakpoints were set at correct locations
- Check which breakpoints have been hit (times > 0)
- Find breakpoint numbers for deletion
- Confirm file paths resolved correctly

### `gdb_continue`
Continue execution until next breakpoint.

**IMPORTANT:** Only use when program is PAUSED (at a breakpoint). If program hasn't started, use `gdb_execute_command` with "run" instead.

**Example Output:**
```json
{
  "status": "success",
  "message": "Program continued and hit breakpoint 2 at main.cpp:25"
}
```

### `gdb_step`
Step into next instruction (enters functions).

**IMPORTANT:** Only works when program is PAUSED at a specific location.

**Example Output:**
```json
{
  "status": "success",
  "message": "Stepped into function helper() at main.cpp:42"
}
```

### `gdb_next`
Step over to next line (doesn't enter functions).

**IMPORTANT:** Only works when program is PAUSED at a specific location.

**Example Output:**
```json
{
  "status": "success",
  "message": "Stepped over function call, now at main.cpp:43"
}
```

### `gdb_interrupt`
Interrupt (pause) a running program.

**Use when:**
- Program is running and hasn't hit a breakpoint
- You want to pause execution to inspect state
- Program appears stuck and you want to see where it is
- Commands are timing out because program is running

**After interrupting:** You can use `gdb_get_backtrace`, `gdb_get_variables`, etc.

**Example Output:**
```json
{
  "status": "success",
  "message": "Program interrupted at __select() in select.c:28"
}
```

## Data Inspection

### `gdb_evaluate_expression`
Evaluate a C/C++ expression in the current context.

**Parameters:**
- `expression`: Expression to evaluate

**Examples:**
- `"x"` - Get value of variable x
- `"*ptr"` - Dereference pointer
- `"array[5]"` - Access array element
- `"obj->field"` - Access struct field

**Example Output:**
```json
{
  "status": "success",
  "expression": "x + y",
  "value": "42",
  "type": "int"
}
```

### `gdb_get_variables`
Get local variables for a stack frame.

**Parameters:**
- `thread_id` (optional): Thread ID
- `frame`: Frame number (0 is current, default: 0)

**Example Output:**
```json
{
  "status": "success",
  "variables": [
    {
      "name": "x",
      "value": "42",
      "type": "int"
    },
    {
      "name": "str",
      "value": "0x7fffffffde50",
      "type": "const char *"
    },
    {
      "name": "obj",
      "value": "{field1 = 10, field2 = 20}",
      "type": "struct MyStruct"
    }
  ],
  "count": 3
}
```

### `gdb_get_registers`
Get CPU register values for the current frame.

**Example Output:**
```json
{
  "status": "success",
  "registers": {
    "rax": "0x0000000000000000",
    "rbx": "0x0000555555558d60",
    "rcx": "0x00007ffff7a25cf8",
    "rdx": "0x00007fffffffe078",
    "rsi": "0x00007fffffffe068",
    "rdi": "0x0000000000000001",
    "rbp": "0x00007fffffffdf10",
    "rsp": "0x00007fffffffdee8",
    "r8": "0x0000000000000000",
    "r9": "0x00007ffff7fe07d0",
    "r10": "0x0000000000000827",
    "r11": "0x0000000000000206",
    "r12": "0x0000000000000000",
    "r13": "0x0000000000000000",
    "r14": "0x0000000000000000",
    "r15": "0x0000000000000000",
    "rip": "0x0000555555555189"
  },
  "count": 17
}
```

### `gdb_vmmap`
Get the virtual memory map of the debugged process using the GEF `vmmap` command.

**Returns:**
- `status`: "success" or "error"
- `regions`: Array of memory region objects, each containing:
  - `start_address`: Start address in hex (e.g., "0x0000555555554000")
  - `end_address`: End address in hex (e.g., "0x0000555555555000")
  - `size`: Size in bytes (calculated from end - start)
  - `offset`: Offset in file (hex, or "0x0" if not applicable)
  - `permissions`: Permission flags (e.g., "r--", "r-x", "rw-")
  - `path`: File path or region name (e.g., "/usr/lib/libc.so.6", "[heap]", "[stack]")
  - `type`: Region type: "code", "data", "heap", "stack", "library", "system", or "unknown"
- `count`: Number of memory regions

**Use Cases:**
- Understand the process memory layout
- Locate code sections and their addresses
- Find heap and stack memory regions
- Identify library mappings and ASLR (Address Space Layout Randomization)
- Analyze memory protection settings

**Example Output:**
```json
{
  "status": "success",
  "count": 21,
  "regions": [
    {
      "start_address": "0x0000555555554000",
      "end_address": "0x0000555555555000",
      "size": 4096,
      "offset": "0x0000000000000000",
      "permissions": "r--",
      "path": "/home/unicorn/Documents/gef-mcp/examples/sample_program",
      "type": "data"
    },
    {
      "start_address": "0x0000555555555000",
      "end_address": "0x0000555555556000",
      "size": 4096,
      "offset": "0x0000000000001000",
      "permissions": "r-x",
      "path": "/home/unicorn/Documents/gef-mcp/examples/sample_program",
      "type": "code"
    },
    {
      "start_address": "0x00007ffffffde000",
      "end_address": "0x00007ffffffff000",
      "size": 139264,
      "offset": "0x0000000000000000",
      "permissions": "rw-",
      "path": "[stack]",
      "type": "stack"
    }
  ]
}
```

## Pwntools Integration

Tools for attaching to and debugging processes spawned by pwntools exploit scripts.

### `gdb_attach_pid`
Attach GDB to a running process by PID.

**Parameters:**
- `pid` (required): Process ID to attach to
- `binary` (optional): Path to executable for symbol resolution
- `working_dir` (optional): Working directory for GDB

**Example:**
```json
{"pid": 12345, "binary": "./chall"}
```

### `gdb_find_processes`
Find running processes by name substring.

**Parameters:**
- `name` (required): Process name substring to search for (case-insensitive)
- `limit` (optional): Maximum results (default: 20, range: 1-200)

**Example:**
```json
{"name": "chall", "limit": 10}
```

**Example Output:**
```json
{
  "status": "success",
  "name": "chall",
  "matches": [
    {"pid": 54321, "comm": "chall", "exe": "/home/user/chall", "cmdline": "./chall"}
  ]
}
```

### `gdb_wait_for_process`
Wait for a process matching name to appear. Polls periodically until found or timeout.

**Parameters:**
- `name` (required): Process name substring to wait for
- `timeout_sec` (optional): Max wait time in seconds (default: 10, range: 0-300)
- `poll_interval_sec` (optional): Poll interval in seconds (default: 0.2, range: 0-5)

### `gdb_attach_by_name`
Wait for a process by name, then attach GDB to it. Combines wait + attach.

**Parameters:**
- `name` (required): Process name substring to find and attach to
- `binary` (optional): Path to executable for symbol resolution
- `working_dir` (optional): Working directory for GDB
- `timeout_sec` (optional): Max wait time in seconds (default: 10)

### `gdb_pwntools_attach_and_break`
All-in-one: wait for process → attach GDB → apply exploit settings → set breakpoints.

**This is the recommended tool for the typical pwntools workflow.**

**Parameters:**
- `name` (required): Process name substring to find and attach to
- `breakpoints` (required): List of breakpoint locations (e.g., `["main", "*0x40123a"]`)
- `binary` (optional): Path to executable for symbol resolution
- `working_dir` (optional): Working directory for GDB
- `timeout_sec` (optional): Max wait time (default: 10)
- `follow_fork_mode` (optional): `"parent"` or `"child"` (default: `"parent"`)
- `detach_on_fork` (optional): Detach from child on fork (default: true)

**Example:**
```json
{
  "name": "chall",
  "breakpoints": ["main", "*0x40123a"],
  "binary": "./chall",
  "timeout_sec": 15
}
```

**Typical workflow:**
```python
# In pwntools script:
p = process('./chall')
pause()  # Wait for MCP to attach
```
```
# Then via MCP:
gdb_pwntools_attach_and_break(name="chall", breakpoints=["main"], binary="./chall")
gdb_continue()
# ... inspect state, set more breakpoints, etc.
```

### `gdb_pwntools_bootstrap`
Apply exploit-friendly settings on an already-attached session.

Sets: follow-fork-mode, detach-on-fork, intel disasm, pagination off, asm-demangle, disassemble-next-line.

**Parameters:**
- `breakpoints` (optional): List of breakpoint locations to set
- `follow_fork_mode` (optional): `"parent"` or `"child"` (default: `"parent"`)
- `detach_on_fork` (optional): Detach from child on fork (default: true)

### `gdb_generate_pwntools_gdbscript`
Generate a pwntools `gdb.attach()` gdbscript string.

**Parameters:**
- `breakpoints` (optional): List of breakpoint locations
- `commands` (optional): Additional GDB commands
- `continue_after` (optional): Add `c` at end (default: true)

**Example Output:**
```json
{
  "status": "success",
  "gdbscript": "set pagination off\nset disassembly-flavor intel\nb main\nb *0x401234\nc"
}
```

Use in pwntools: `gdb.attach(p, gdbscript=result['gdbscript'])`

