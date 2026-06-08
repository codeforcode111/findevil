from __future__ import annotations

import re
from dataclasses import dataclass


class CommandValidationError(Exception):
    pass


@dataclass
class ToolDefinition:
    name: str
    binary: str
    description: str
    allowed_args_pattern: str | None = None


ALLOWED_TOOLS: dict[str, ToolDefinition] = {
    "vol": ToolDefinition("vol", "vol", "Volatility 3 memory forensics framework"),
    "fls": ToolDefinition("fls", "fls", "Sleuth Kit file listing"),
    "icat": ToolDefinition("icat", "icat", "Sleuth Kit file extraction by inode"),
    "mmls": ToolDefinition("mmls", "mmls", "Sleuth Kit partition table display"),
    "img_stat": ToolDefinition("img_stat", "img_stat", "Sleuth Kit image info"),
    "log2timeline": ToolDefinition("log2timeline", "log2timeline.py", "Plaso super-timeline"),
    "psort": ToolDefinition("psort", "psort.py", "Plaso timeline sorting/filtering"),
    "hayabusa": ToolDefinition("hayabusa", "hayabusa", "Windows EVTX analysis with Sigma"),
    "yara": ToolDefinition("yara", "yara", "YARA pattern matching"),
    "regripper": ToolDefinition("regripper", "rip.pl", "Registry analysis"),
    "mftecmd": ToolDefinition("mftecmd", "MFTECmd", "MFT parser"),
    "pecmd": ToolDefinition("pecmd", "PECmd", "Prefetch parser"),
    "amcacheparser": ToolDefinition("amcacheparser", "AmcacheParser", "Amcache parser"),
    "strings": ToolDefinition("strings", "strings", "Extract printable strings"),
    "sha256sum": ToolDefinition("sha256sum", "sha256sum", "Compute SHA-256 hash"),
}

BLOCKED_COMMANDS = frozenset({
    "rm", "rmdir", "dd", "mkfs", "fdisk", "shred",
    "chmod", "chown", "mount", "umount", "kill",
    "reboot", "shutdown", "poweroff", "curl", "wget",
    "nc", "ncat", "python", "python3", "bash", "sh",
    "perl", "ruby", "pip", "apt", "yum",
})

SHELL_METACHARS = re.compile(r"[;&|`$(){}]")

ALLOWED_PATHS = ("/evidence", "/workspace")


class ToolRegistry:
    def validate(self, command: str, args: list[str]) -> None:
        if command in BLOCKED_COMMANDS:
            raise CommandValidationError(
                f"Command '{command}' is blocked: destructive or dangerous operation"
            )

        if command not in ALLOWED_TOOLS:
            raise CommandValidationError(
                f"Command '{command}' is not in the allowed tools list"
            )

        full_args = " ".join(args)
        if SHELL_METACHARS.search(full_args):
            raise CommandValidationError(
                f"Shell metacharacter injection detected in arguments: {full_args}"
            )

        for arg in args:
            if arg.startswith("/") and not arg.startswith(ALLOWED_PATHS):
                resolved = arg.replace("/..", "")
                if not resolved.startswith(ALLOWED_PATHS):
                    raise CommandValidationError(
                        f"Path '{arg}' is outside the allowed boundary "
                        f"(must be under {ALLOWED_PATHS})"
                    )

    def get_tool_info(self, name: str) -> dict[str, str] | None:
        tool = ALLOWED_TOOLS.get(name)
        if tool is None:
            return None
        return {
            "name": tool.name,
            "binary": tool.binary,
            "description": tool.description,
        }

    def list_tools(self) -> list[dict[str, str]]:
        return [
            {"name": t.name, "binary": t.binary, "description": t.description}
            for t in ALLOWED_TOOLS.values()
        ]
