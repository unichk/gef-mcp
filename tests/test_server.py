"""Unit tests for MCP server."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from pydantic import ValidationError
from gdb_mcp.server import (
    StartSessionArgs,
    ExecuteCommandArgs,
    GetBacktraceArgs,
    SetBreakpointArgs,
    EvaluateExpressionArgs,
    GetVariablesArgs,
)


class TestStartSessionArgs:
    """Test cases for StartSessionArgs model."""

    def test_minimal_args(self):
        """Test creating StartSessionArgs with minimal arguments."""
        args = StartSessionArgs()
        assert args.program is None
        assert args.args is None
        assert args.init_commands is None
        assert args.env is None
        assert (
            args.gdb_path is None
        )  # Default to None, actual default determined by GDB_PATH env var or "gdb"

    def test_full_args(self):
        """Test creating StartSessionArgs with all arguments."""
        args = StartSessionArgs(
            program="/bin/ls",
            args=["-la", "/tmp"],
            init_commands=["set pagination off"],
            env={"DEBUG": "1"},
            gdb_path="/usr/local/bin/gdb",
        )

        assert args.program == "/bin/ls"
        assert args.args == ["-la", "/tmp"]
        assert args.init_commands == ["set pagination off"]
        assert args.env == {"DEBUG": "1"}
        assert args.gdb_path == "/usr/local/bin/gdb"

    def test_env_dict_validation(self):
        """Test that env accepts dictionary of strings."""
        args = StartSessionArgs(program="/bin/ls", env={"VAR1": "value1", "VAR2": "value2"})

        assert args.env == {"VAR1": "value1", "VAR2": "value2"}


class TestExecuteCommandArgs:
    """Test cases for ExecuteCommandArgs model."""

    def test_command_required(self):
        """Test that command is required."""
        with pytest.raises(ValidationError):
            ExecuteCommandArgs()

    def test_command_arg(self):
        """Test command argument."""
        args = ExecuteCommandArgs(command="info threads")
        assert args.command == "info threads"


class TestGetBacktraceArgs:
    """Test cases for GetBacktraceArgs model."""

    def test_defaults(self):
        """Test default values."""
        args = GetBacktraceArgs()
        assert args.thread_id is None
        assert args.max_frames == 100

    def test_with_thread_id(self):
        """Test with specific thread ID."""
        args = GetBacktraceArgs(thread_id=5, max_frames=50)
        assert args.thread_id == 5
        assert args.max_frames == 50


class TestSetBreakpointArgs:
    """Test cases for SetBreakpointArgs model."""

    def test_location_required(self):
        """Test that location is required."""
        with pytest.raises(ValidationError):
            SetBreakpointArgs()

    def test_minimal_breakpoint(self):
        """Test minimal breakpoint (just location)."""
        args = SetBreakpointArgs(location="main")
        assert args.location == "main"
        assert args.condition is None
        assert args.temporary is False

    def test_conditional_breakpoint(self):
        """Test conditional breakpoint."""
        args = SetBreakpointArgs(location="foo.c:42", condition="x > 10", temporary=True)
        assert args.location == "foo.c:42"
        assert args.condition == "x > 10"
        assert args.temporary is True


class TestEvaluateExpressionArgs:
    """Test cases for EvaluateExpressionArgs model."""

    def test_expression_required(self):
        """Test that expression is required."""
        with pytest.raises(ValidationError):
            EvaluateExpressionArgs()

    def test_expression(self):
        """Test with expression."""
        args = EvaluateExpressionArgs(expression="x + y")
        assert args.expression == "x + y"


class TestGetVariablesArgs:
    """Test cases for GetVariablesArgs model."""

    def test_defaults(self):
        """Test default values."""
        args = GetVariablesArgs()
        assert args.thread_id is None
        assert args.frame == 0

    def test_with_values(self):
        """Test with specific values."""
        args = GetVariablesArgs(thread_id=3, frame=2)
        assert args.thread_id == 3
        assert args.frame == 2


class TestCallFunctionArgs:
    """Test cases for CallFunctionArgs model."""

    def test_function_call_required(self):
        """Test that function_call is required."""
        from gdb_mcp.server import CallFunctionArgs

        with pytest.raises(ValidationError):
            CallFunctionArgs()

    def test_function_call_arg(self):
        """Test function_call argument."""
        from gdb_mcp.server import CallFunctionArgs

        args = CallFunctionArgs(function_call='printf("hello")')
        assert args.function_call == 'printf("hello")'

    def test_function_call_with_args(self):
        """Test function_call with multiple arguments."""
        from gdb_mcp.server import CallFunctionArgs

        args = CallFunctionArgs(function_call='snprintf(buf, 100, "%d", x)')
        assert args.function_call == 'snprintf(buf, 100, "%d", x)'


class TestAttachPidArgs:
    """Test cases for AttachPidArgs model."""

    def test_pid_required(self):
        """Test that pid is required."""
        from gdb_mcp.server import AttachPidArgs

        with pytest.raises(ValidationError):
            AttachPidArgs()

    def test_minimal(self):
        """Test with just pid."""
        from gdb_mcp.server import AttachPidArgs

        args = AttachPidArgs(pid=12345)
        assert args.pid == 12345
        assert args.binary is None
        assert args.working_dir is None

    def test_full(self):
        """Test with all args."""
        from gdb_mcp.server import AttachPidArgs

        args = AttachPidArgs(pid=12345, binary="./chall", working_dir="/tmp")
        assert args.pid == 12345
        assert args.binary == "./chall"
        assert args.working_dir == "/tmp"


class TestFindProcessesArgs:
    """Test cases for FindProcessesArgs model."""

    def test_name_required(self):
        from gdb_mcp.server import FindProcessesArgs

        with pytest.raises(ValidationError):
            FindProcessesArgs()

    def test_defaults(self):
        from gdb_mcp.server import FindProcessesArgs

        args = FindProcessesArgs(name="chall")
        assert args.name == "chall"
        assert args.limit == 20


class TestPwntoolsAttachAndBreakArgs:
    """Test cases for PwntoolsAttachAndBreakArgs model."""

    def test_required_fields(self):
        from gdb_mcp.server import PwntoolsAttachAndBreakArgs

        with pytest.raises(ValidationError):
            PwntoolsAttachAndBreakArgs()

    def test_full(self):
        from gdb_mcp.server import PwntoolsAttachAndBreakArgs

        args = PwntoolsAttachAndBreakArgs(
            name="chall",
            breakpoints=["main", "*0x401234"],
            binary="./chall",
            follow_fork_mode="child",
            detach_on_fork=False,
        )
        assert args.name == "chall"
        assert args.breakpoints == ["main", "*0x401234"]
        assert args.follow_fork_mode == "child"
        assert args.detach_on_fork is False


class TestGenerateGdbscriptArgs:
    """Test cases for GenerateGdbscriptArgs model."""

    def test_defaults(self):
        from gdb_mcp.server import GenerateGdbscriptArgs

        args = GenerateGdbscriptArgs()
        assert args.breakpoints is None
        assert args.commands is None
        assert args.continue_after is True

    def test_full(self):
        from gdb_mcp.server import GenerateGdbscriptArgs

        args = GenerateGdbscriptArgs(
            breakpoints=["main"], commands=["x/20gx $rsp"], continue_after=False
        )
        assert args.breakpoints == ["main"]
        assert args.commands == ["x/20gx $rsp"]
        assert args.continue_after is False
