import subprocess

import psutil

from backdoor_watch.collectors.signature_verifier import SignatureVerifier
from backdoor_watch.domain.process import ProcessInfo

_ATTRS = ["pid", "name", "exe", "cmdline", "username", "create_time", "cpu_percent", "memory_info"]


def _parent_map() -> dict[int, int]:
    """psutil's per-process ppid() takes a full system snapshot each call (O(n²), ~10s for
    600 processes). The private ppid_map() does it once; fall back if it ever disappears."""
    ppid_map = getattr(getattr(psutil, "_psplatform", None), "cext", None)
    if ppid_map is not None and hasattr(ppid_map, "ppid_map"):
        return ppid_map.ppid_map()
    return {p.pid: p.info["ppid"] for p in psutil.process_iter(["ppid"], ad_value=None)}


class ProcessCollector:
    def __init__(self, signatures: SignatureVerifier) -> None:
        self._signatures = signatures

    def snapshot(self) -> list[ProcessInfo]:
        parents = _parent_map()
        return [self._to_model(proc.info, parents.get(proc.pid))
                for proc in psutil.process_iter(_ATTRS, ad_value=None)]

    def _to_model(self, info: dict, ppid: int | None) -> ProcessInfo:
        exe = info.get("exe") or None
        memory = info.get("memory_info")
        cmdline = info.get("cmdline") or []
        return ProcessInfo(
            pid=info["pid"],
            ppid=ppid,
            name=info.get("name") or "?",
            exe=exe,
            cmdline=subprocess.list2cmdline(cmdline) if cmdline else "",
            username=info.get("username"),
            create_time=info.get("create_time"),
            cpu_percent=info.get("cpu_percent"),
            memory_mb=round(memory.rss / 1_048_576, 1) if memory else None,
            signature=self._signatures.lookup(exe),
        )
