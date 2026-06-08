from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def create_timeline(
    executor: DockerExecutor,
    source_path: str,
    output_path: str = "/workspace/timeline.plaso",
) -> ExecutionResult:
    args = [
        "--status_view", "none",
        source_path,
        output_path,
    ]
    return executor.execute("log2timeline", args)


def sort_timeline(
    executor: DockerExecutor,
    plaso_path: str,
    output_path: str = "/workspace/timeline.csv",
    time_filter: str | None = None,
) -> ExecutionResult:
    args = [
        "-o", "l2tcsv",
        "-w", output_path,
        plaso_path,
    ]
    if time_filter:
        args.extend(["--slice", time_filter])
    return executor.execute("psort", args)
