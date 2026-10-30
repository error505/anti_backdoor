from backdoor_watch.domain.activity import ActivityKind
from backdoor_watch.domain.network import Connection
from backdoor_watch.monitoring.snapshot_diff import diff_connections


def _conn(remote_ip: str, external: bool, state: str = "ESTABLISHED") -> Connection:
    return Connection(protocol="tcp", family="ipv4", local_ip="10.0.0.5", local_port=50000,
                      remote_ip=remote_ip, remote_port=443, state=state, pid=7, process_name="node.exe",
                      is_external=external)


def test_new_external_connection_produces_open_event():
    conn = _conn("8.8.8.8", external=True)
    events = diff_connections({}, {conn.key(): conn})
    assert [e.kind for e in events] == [ActivityKind.CONNECTION_OPENED]


def test_local_network_chatter_is_not_recorded():
    conn = _conn("192.168.1.10", external=False)
    assert diff_connections({}, {conn.key(): conn}) == []


def test_closed_external_connection_produces_close_event():
    conn = _conn("8.8.8.8", external=True)
    events = diff_connections({conn.key(): conn}, {})
    assert [e.kind for e in events] == [ActivityKind.CONNECTION_CLOSED]
