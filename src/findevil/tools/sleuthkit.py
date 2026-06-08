from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult


def list_files(
    executor: DockerExecutor,
    image_path: str,
    offset: int | None = None,
    path: str = "/",
    recursive: bool = False,
) -> ExecutionResult:
    args = []
    if offset is not None:
        args.extend(["-o", str(offset)])
    if recursive:
        args.append("-r")
    args.extend([image_path, path])
    return executor.execute("fls", args)


def extract_file(
    executor: DockerExecutor,
    image_path: str,
    inode: str,
    offset: int | None = None,
) -> ExecutionResult:
    args = []
    if offset is not None:
        args.extend(["-o", str(offset)])
    args.extend([image_path, inode])
    return executor.execute("icat", args)


def partition_table(
    executor: DockerExecutor,
    image_path: str,
) -> ExecutionResult:
    return executor.execute("mmls", [image_path])


def image_info(
    executor: DockerExecutor,
    image_path: str,
) -> ExecutionResult:
    return executor.execute("img_stat", [image_path])
