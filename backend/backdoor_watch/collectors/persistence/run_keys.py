import winreg

from backdoor_watch.domain.command_line import extract_image_path
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind, make_entry_id

HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}

_RUN_LOCATIONS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
]


def _read_values(hive_name: str, subkey: str) -> list[tuple[str, str]]:
    try:
        key = winreg.OpenKey(HIVES[hive_name], subkey, 0, winreg.KEY_READ)
    except OSError:
        return []
    values = []
    with key:
        index = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, index)
            except OSError:
                break
            values.append((name, str(data)))
            index += 1
    return values


class RunKeyCollector:
    def collect(self) -> list[PersistenceEntry]:
        entries = []
        for hive_name, subkey in _RUN_LOCATIONS:
            location = f"{hive_name}\\{subkey}"
            for name, command in _read_values(hive_name, subkey):
                entries.append(PersistenceEntry(
                    id=make_entry_id(PersistenceKind.RUN_KEY, location, name),
                    kind=PersistenceKind.RUN_KEY, name=name or "(Default)", location=location,
                    command=command, image_path=extract_image_path(command),
                    details={"hive": hive_name, "subkey": subkey, "value_name": name},
                ))
        return entries
