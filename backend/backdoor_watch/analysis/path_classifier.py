import ntpath
import os

from backdoor_watch.analysis.ioc_rules import IocRules

_HOME = os.path.normcase(os.path.expanduser("~")).rstrip("\\") + "\\"
_PROGRAM_FILES = tuple(os.path.normcase(os.environ.get(var, default)).rstrip("\\") + "\\" for var, default in (
    ("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", r"C:\Program Files (x86)")))


class PathClassifier:
    """Answers location questions about executables using the configured rules."""

    def __init__(self, rules: IocRules) -> None:
        self._rules = rules

    def is_user_writable(self, path: str | None) -> bool:
        if not path:
            return False
        normalized = os.path.normcase(path)
        return any(normalized.startswith(d) for d in self._rules.user_writable_dirs)

    @staticmethod
    def is_in_hidden_home_dir(path: str | None) -> bool:
        """e.g. C:\\Users\\me\\.pyp\\python.exe: dot-folders are where InvisibleFerret hides."""
        if not path:
            return False
        normalized = os.path.normcase(path)
        if not normalized.startswith(_HOME):
            return False
        first_component = normalized[len(_HOME):].split("\\", 1)[0]
        return first_component.startswith(".")

    def is_script_host(self, path_or_name: str | None) -> bool:
        return bool(path_or_name) and ntpath.basename(path_or_name).lower() in self._rules.script_hosts

    def remote_access_tool(self, path_or_name: str | None) -> str | None:
        if not path_or_name:
            return None
        base = ntpath.basename(path_or_name).lower()
        return next((tool for tool in self._rules.remote_access_tools if tool in base), None)

    def is_suspicious_location(self, path: str | None) -> bool:
        return self.is_user_writable(path) or self.is_in_hidden_home_dir(path)

    def references_user_writable(self, command: str) -> bool:
        normalized = os.path.normcase(command)
        return any(d in normalized for d in self._rules.user_writable_dirs)

    @staticmethod
    def is_admin_protected_install(path: str | None) -> bool:
        """Program Files needs admin rights to write, so unsigned binaries there are lower risk."""
        # realpath expands 8.3 short names such as C:\PROGRA~1 used by some service paths.
        return bool(path) and os.path.normcase(os.path.realpath(path)).startswith(_PROGRAM_FILES)
