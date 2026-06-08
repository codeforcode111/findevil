from __future__ import annotations

from findevil.tools.executor import DockerExecutor, ExecutionResult

PLUGINS = {
    "pslist": "windows.pslist.PsList",
    "psscan": "windows.psscan.PsScan",
    "netscan": "windows.netscan.NetScan",
    "malfind": "windows.malfind.Malfind",
    "cmdline": "windows.cmdline.CmdLine",
    "filescan": "windows.filescan.FileScan",
    "dlllist": "windows.dlllist.DllList",
    "handles": "windows.handles.Handles",
    "svcscan": "windows.svcscan.SvcScan",
    "hivelist": "windows.registry.hivelist.HiveList",
}


def run_plugin(
    executor: DockerExecutor,
    dump_path: str,
    plugin: str,
    extra_args: list[str] | None = None,
) -> ExecutionResult:
    plugin_class = PLUGINS.get(plugin, plugin)
    args = ["-f", dump_path, plugin_class]
    if extra_args:
        args.extend(extra_args)
    return executor.execute("vol", args)


def list_plugins() -> list[dict[str, str]]:
    return [{"name": k, "class": v} for k, v in PLUGINS.items()]
