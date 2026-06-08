from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def scan_evtx(
    executor: DockerExecutor,
    evtx_path: str,
    output_path: str = "/workspace/hayabusa_results.csv",
    min_level: str = "medium",
) -> ExecutionResult:
    args = [
        "csv-timeline",
        "-d", evtx_path,
        "-o", output_path,
        "--min-level", min_level,
        "-q",
    ]
    return executor.execute("hayabusa", args)


def logon_summary(
    executor: DockerExecutor,
    evtx_path: str,
    output_path: str = "/workspace/logon_summary.csv",
) -> ExecutionResult:
    args = [
        "logon-summary",
        "-d", evtx_path,
        "-o", output_path,
    ]
    return executor.execute("hayabusa", args)
