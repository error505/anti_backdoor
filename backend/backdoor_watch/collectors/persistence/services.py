import psutil

from backdoor_watch.domain.command_line import extract_image_path
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind, make_entry_id

_LOCATION = r"HKLM\SYSTEM\CurrentControlSet\Services"


class ServiceCollector:
    def collect(self) -> list[PersistenceEntry]:
        entries = []
        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except (psutil.Error, OSError):
                continue
            entries.append(self._to_entry(info))
        return entries

    @staticmethod
    def _to_entry(info: dict) -> PersistenceEntry:
        command = info.get("binpath") or ""
        return PersistenceEntry(
            id=make_entry_id(PersistenceKind.SERVICE, _LOCATION, info["name"]),
            kind=PersistenceKind.SERVICE, name=info["name"], location=_LOCATION,
            command=command, image_path=extract_image_path(command) if command else None,
            enabled=info.get("start_type") != "disabled",
            details={"service_name": info["name"],
                     "display_name": info.get("display_name") or "",
                     "start_type": info.get("start_type") or "",
                     "status": info.get("status") or "",
                     "account": info.get("username") or ""},
        )
