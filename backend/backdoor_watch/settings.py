from dataclasses import dataclass
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Settings:
    port: int
    token: str
    data_dir: Path = BACKEND_ROOT / "data"
    # Demo mode shows fictional data and never touches the real system (used for screenshots and trials).
    demo: bool = False
    rules_path: Path = BACKEND_ROOT / "backdoor_watch" / "analysis" / "ioc_rules.json"
    frontend_dist: Path = BACKEND_ROOT.parent / "frontend" / "dist"

    @property
    def install_root(self) -> Path:
        return BACKEND_ROOT.parent

    @property
    def ai_settings_path(self) -> Path:
        return self.data_dir / "ai_settings.json"

    @property
    def intel_settings_path(self) -> Path:
        return self.data_dir / "intel_settings.json"

    @property
    def virustotal_cache_path(self) -> Path:
        return self.data_dir / "virustotal_cache.json"

    @property
    def ip_intel_cache_path(self) -> Path:
        return self.data_dir / "ip_intel_cache.json"

    @property
    def ip_intel_settings_path(self) -> Path:
        return self.data_dir / "ip_intel_settings.json"

    @property
    def known_bad_hashes_path(self) -> Path:
        return self.data_dir / "known_bad_hashes.txt"

    @property
    def flockion_settings_path(self) -> Path:
        return self.data_dir / "flockion_settings.json"

    @property
    def ai_schedule_path(self) -> Path:
        return self.data_dir / "ai_schedule.json"

    @property
    def ai_history_path(self) -> Path:
        return self.data_dir / "ai_history.jsonl"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"
