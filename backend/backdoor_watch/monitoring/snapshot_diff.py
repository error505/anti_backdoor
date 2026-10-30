"""Pure functions turning consecutive snapshots into activity events."""

from collections.abc import Mapping

from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.network import Connection, ConnectionKey
from backdoor_watch.domain.persistence import PersistenceEntry
from backdoor_watch.domain.process import ProcessInfo


def diff_processes(previous: Mapping[int, ProcessInfo], current: Mapping[int, ProcessInfo]) -> list[ActivityEvent]:
    started = [ActivityEvent(kind=ActivityKind.PROCESS_STARTED, pid=p.pid, process_name=p.name,
                             summary=f"Started {p.name} (PID {p.pid})",
                             details={"exe": p.exe or "", "cmdline": p.cmdline[:1000], "ppid": str(p.ppid)})
               for pid, p in current.items() if pid not in previous]
    exited = [ActivityEvent(kind=ActivityKind.PROCESS_EXITED, pid=p.pid, process_name=p.name,
                            summary=f"Exited {p.name} (PID {p.pid})", details={"exe": p.exe or ""})
              for pid, p in previous.items() if pid not in current]
    return started + exited


def _is_tracked(conn: Connection) -> bool:
    """External TCP sessions and listeners; local chatter would drown the timeline."""
    return (conn.protocol == "tcp" and conn.is_external) or conn.state == "LISTEN"


def _connection_event(conn: Connection, opened: bool) -> ActivityEvent:
    if conn.state == "LISTEN":
        kind = ActivityKind.LISTENER_OPENED if opened else ActivityKind.LISTENER_CLOSED
        summary = f"{'Opened' if opened else 'Closed'} listening port {conn.local_ip}:{conn.local_port}"
    else:
        kind = ActivityKind.CONNECTION_OPENED if opened else ActivityKind.CONNECTION_CLOSED
        address = f"[{conn.remote_ip}]" if conn.family == "ipv6" else conn.remote_ip
        remote = f"{conn.remote_host or address}:{conn.remote_port}"
        summary = f"{'Connected to' if opened else 'Disconnected from'} {remote}"
    return ActivityEvent(kind=kind, pid=conn.pid, process_name=conn.process_name,
                         summary=f"{conn.process_name or 'unknown'}: {summary}",
                         details={"remote_ip": conn.remote_ip or "", "remote_port": str(conn.remote_port or ""),
                                  "local": f"{conn.local_ip}:{conn.local_port}", "exposure": conn.exposure})


def diff_connections(previous: Mapping[ConnectionKey, Connection],
                     current: Mapping[ConnectionKey, Connection]) -> list[ActivityEvent]:
    opened = [_connection_event(c, True) for k, c in current.items() if k not in previous and _is_tracked(c)]
    closed = [_connection_event(c, False) for k, c in previous.items() if k not in current and _is_tracked(c)]
    return opened + closed


def diff_persistence(previous: Mapping[str, PersistenceEntry],
                     current: Mapping[str, PersistenceEntry]) -> list[ActivityEvent]:
    added = [ActivityEvent(kind=ActivityKind.PERSISTENCE_ADDED,
                           summary=f"NEW autostart entry: {e.kind.value} '{e.name}'",
                           details={"location": e.location, "command": e.command[:1000]})
             for key, e in current.items() if key not in previous]
    removed = [ActivityEvent(kind=ActivityKind.PERSISTENCE_REMOVED,
                             summary=f"Autostart entry gone: {e.kind.value} '{e.name}'",
                             details={"location": e.location, "command": e.command[:1000]})
               for key, e in previous.items() if key not in current]
    return added + removed
