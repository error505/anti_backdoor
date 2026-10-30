import re

from pydantic import BaseModel, computed_field

_COMMON_NAME = re.compile(r'CN="?([^,"]+)')
_UNTRUSTED_STATUSES = frozenset({"NotSigned", "HashMismatch", "NotTrusted", "Incompatible"})


class SignatureInfo(BaseModel, frozen=True):
    status: str
    subject: str | None = None

    @computed_field
    @property
    def signer(self) -> str | None:
        if not self.subject:
            return None
        match = _COMMON_NAME.search(self.subject)
        return match.group(1).strip() if match else self.subject

    @computed_field
    @property
    def is_valid(self) -> bool:
        return self.status == "Valid"

    @computed_field
    @property
    def is_untrusted(self) -> bool:
        """Positively bad: unsigned or tampered. 'Unreadable'/'Unknown' (e.g. protected
        WindowsApps folders) are not evidence either way."""
        return self.status in _UNTRUSTED_STATUSES

    @computed_field
    @property
    def is_microsoft(self) -> bool:
        return self.is_valid and "microsoft" in (self.subject or "").lower()


class ProcessInfo(BaseModel):
    pid: int
    ppid: int | None
    name: str
    exe: str | None
    cmdline: str
    username: str | None
    create_time: float | None
    cpu_percent: float | None
    memory_mb: float | None
    signature: SignatureInfo | None = None
