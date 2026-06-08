from __future__ import annotations

import hashlib
import subprocess
import time
from dataclasses import dataclass, field

from findevil.audit.ledger import AuditLedger
from findevil.tools.registry import ToolRegistry


class ToolExecutionError(Exception):
    pass


@dataclass
class ExecutionResult:
    run_id: str
    tool: str
    command: str
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    stdout_hash: str
    duration_ms: int


class DockerExecutor:
    def __init__(
        self,
        container_name: str,
        registry: ToolRegistry,
        ledger: AuditLedger,
        timeout: int = 300,
        max_retries: int = 2,
    ) -> None:
        self.container_name = container_name
        self.registry = registry
        self.ledger = ledger
        self.timeout = timeout
        self.max_retries = max_retries
        self._run_counter = 0

    def _next_run_id(self) -> str:
        self._run_counter += 1
        return f"run-{self._run_counter:04d}"

    def execute(
        self,
        tool: str,
        args: list[str],
        retry_count: int = 0,
    ) -> ExecutionResult:
        self.registry.validate(tool, args)

        tool_info = self.registry.get_tool_info(tool)
        binary = tool_info["binary"] if tool_info else tool

        docker_cmd = [
            "docker", "exec", self.container_name,
            binary, *args,
        ]

        run_id = self._next_run_id()
        start = time.monotonic()

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - start) * 1000)
            self.ledger.append("tool_call", {
                "run_id": run_id,
                "tool": tool,
                "command": " ".join(docker_cmd),
                "exit_code": -1,
                "error": "timed_out",
                "duration_ms": duration_ms,
            })
            raise ToolExecutionError(
                f"Tool '{tool}' timed out after {self.timeout}s"
            )

        duration_ms = int((time.monotonic() - start) * 1000)
        stdout_hash = hashlib.sha256(proc.stdout.encode()).hexdigest()

        result = ExecutionResult(
            run_id=run_id,
            tool=tool,
            command=" ".join(docker_cmd),
            args=args,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            stdout_hash=stdout_hash,
            duration_ms=duration_ms,
        )

        self.ledger.append("tool_call", {
            "run_id": run_id,
            "tool": tool,
            "command": result.command,
            "args": args,
            "exit_code": result.exit_code,
            "stdout_hash": stdout_hash,
            "stderr_snippet": proc.stderr[:500] if proc.stderr else "",
            "duration_ms": duration_ms,
        })

        return result
