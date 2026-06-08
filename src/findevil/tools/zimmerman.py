from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def parse_mft(
    executor: DockerExecutor,
    mft_path: str,
    output_path: str = "/workspace/mft_output.csv",
) -> ExecutionResult:
    args = ["-f", mft_path, "--csv", output_path]
    return executor.execute("mftecmd", args)


def parse_prefetch(
    executor: DockerExecutor,
    prefetch_dir: str,
    output_path: str = "/workspace/prefetch_output.csv",
) -> ExecutionResult:
    args = ["-d", prefetch_dir, "--csv", output_path]
    return executor.execute("pecmd", args)


def parse_amcache(
    executor: DockerExecutor,
    amcache_path: str,
    output_path: str = "/workspace/amcache_output.csv",
) -> ExecutionResult:
    args = ["-f", amcache_path, "--csv", output_path]
    return executor.execute("amcacheparser", args)


def analyze_registry(
    executor: DockerExecutor,
    hive_path: str,
    plugin: str | None = None,
) -> ExecutionResult:
    args = ["-r", hive_path]
    if plugin:
        args.extend(["-p", plugin])
    return executor.execute("regripper", args)
