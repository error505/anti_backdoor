from enum import Enum

from pydantic import BaseModel


class ActivityKind(str, Enum):
    MONITORING_STARTED = "monitoring_started"
    PROCESS_STARTED = "process_started"
    PROCESS_EXITED = "process_exited"
    CONNECTION_OPENED = "connection_opened"
    CONNECTION_CLOSED = "connection_closed"
    LISTENER_OPENED = "listener_opened"
    LISTENER_CLOSED = "listener_closed"
    PERSISTENCE_ADDED = "persistence_added"
    PERSISTENCE_REMOVED = "persistence_removed"
    ACTION_TAKEN = "action_taken"


class ActivityEvent(BaseModel):
    kind: ActivityKind
    summary: str
    pid: int | None = None
    process_name: str | None = None
    details: dict[str, str] = {}
    seq: int = 0
    timestamp: float = 0.0
