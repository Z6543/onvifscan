"""
Common data structures and output formatting for ONVIF security scanner.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import json


@dataclass
class ToolConfig:
    """Configuration for running a tool."""
    input_paths: List[str]
    output_format: str = 'text'  # 'text', 'json', 'quiet'
    verbose: bool = False
    timeout: Optional[float] = None
    custom_args: Dict[str, Any] = field(default_factory=dict)

    @property
    def input_path(self) -> str:
        """Backward compatibility property for tools expecting a single path."""
        return self.input_paths[0] if self.input_paths else ""


@dataclass
class ToolResult:
    """Standardized result structure from tool execution."""
    success: bool
    data: Any = None
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0


class OutputFormatter:
    """Handles formatting tool results for different output formats."""

    def format_result(self, result: ToolResult, format_type: str) -> str:
        """Format a ToolResult according to the specified format."""
        if format_type == 'json':
            return self._format_json(result)
        elif format_type == 'text':
            return self._format_text(result)
        elif format_type == 'quiet':
            return self._format_quiet(result)
        else:
            raise ValueError(f"Unknown format type: {format_type}")

    def _format_json(self, result: ToolResult) -> str:
        """Format result as JSON."""
        return json.dumps(asdict(result), indent=2, default=str)

    def _format_text(self, result: ToolResult) -> str:
        """Format result as human-readable text. Override in subclasses."""
        lines = []
        if result.success:
            lines.append("SUCCESS: Tool executed successfully")
        else:
            lines.append("FAILED: Tool execution failed")

        if result.errors:
            lines.append("Errors:")
            for error in result.errors:
                lines.append(f"  - {error}")

        if result.metadata:
            lines.append("Metadata:")
            for key, value in result.metadata.items():
                lines.append(f"  {key}: {value}")

        if result.execution_time > 0:
            lines.append(f"Execution time: {result.execution_time:.2f}s")

        return "\n".join(lines)

    def _format_quiet(self, result: ToolResult) -> str:
        """Format result for quiet mode (minimal output)."""
        return "" if result.success else "\n".join(result.errors)


class ConfigBuilder:
    """Helper class to build ToolConfig from various sources."""

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ToolConfig:
        """Create ToolConfig from dictionary."""
        return ToolConfig(**data)

    @staticmethod
    def from_args(args, tool_name: str) -> ToolConfig:
        """Create ToolConfig from argparse args."""
        custom_args = {}

        # Extract common args
        input_paths = getattr(args, 'paths', getattr(args, 'path', None))
        if input_paths is None:
            input_paths = getattr(args, 'target', getattr(args, 'input', getattr(args, 'hostname', getattr(args, 'url', ''))))
            if input_paths and not isinstance(input_paths, list):
                input_paths = [input_paths]
        elif not isinstance(input_paths, list):
            input_paths = [input_paths]

        output_format = getattr(args, 'format', getattr(args, 'output', 'text'))
        verbose = getattr(args, 'verbose', False)
        timeout = getattr(args, 'timeout', None)

        # Tool-specific custom args
        if hasattr(args, 'all'):
            custom_args['all'] = args.all

        return ToolConfig(
            input_paths=input_paths,
            output_format=output_format,
            verbose=verbose,
            timeout=timeout,
            custom_args=custom_args
        )
