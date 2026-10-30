from enum import Enum

from pydantic import BaseModel, Field


class GuardMode(str, Enum):
    OFF = "off"
    ALERT = "alert"
    CONTAIN = "contain"


class TrustKind(str, Enum):
    PUBLISHER = "publisher"
    PROGRAM = "program"


class TrustEntry(BaseModel):
    """A program or publisher the user authorised to send data out. A program entry pins the file's SHA-256,
    so replacing the file (a classic way to hijack a trusted path) revokes the trust."""
    id: str
    kind: TrustKind
    value: str
    sha256: str | None = None
    added_at: float


class GuardConfig(BaseModel):
    install_watch: GuardMode = GuardMode.CONTAIN
    lockdown: GuardMode = GuardMode.OFF
    sound: bool = True
    trusted: list[TrustEntry] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)


class GuardAlertKind(str, Enum):
    INSTALL_LEAK = "install_leak"
    UNTRUSTED_OUTBOUND = "untrusted_outbound"


class GuardAlert(BaseModel):
    id: str
    created_at: float
    kind: GuardAlertKind
    title: str
    pid: int
    process_name: str
    exe: str | None
    chain: list[str]
    remote_ip: str
    remote_port: int | None
    remote_host: str | None
    action: str
    detail: str
    contained_pids: list[int] = Field(default_factory=list)
    acknowledged: bool = False


class SeenProgram(BaseModel):
    """A program that talks to the internet and is not trusted yet: the list to review before turning lockdown on."""
    name: str
    exe: str | None
    signer: str | None
    validly_signed: bool
    connections: int
    remotes: list[str]


class GuardStatus(BaseModel):
    config: GuardConfig
    default_allowed_hosts: list[str]
    alerts: list[GuardAlert]
    unacknowledged: int
    seen_programs: list[SeenProgram]
