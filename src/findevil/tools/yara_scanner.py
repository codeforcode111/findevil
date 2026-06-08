from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def scan(
    executor: DockerExecutor,
    rules_path: str,
    target_path: str,
    recursive: bool = True,
) -> ExecutionResult:
    args = []
    if recursive:
        args.append("-r")
    args.extend([rules_path, target_path])
    return executor.execute("yara", args)
