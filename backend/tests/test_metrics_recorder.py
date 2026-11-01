from backdoor_watch.domain.findings import Finding, FindingTargetKind, Severity
from backdoor_watch.domain.network import Connection
from backdoor_watch.monitoring.metrics_recorder import MetricsRecorder
from backdoor_watch.monitoring.system_state import SystemState
from backdoor_watch.monitoring.traffic_ledger import TrafficLedger


def connection(remote_ip, state="ESTABLISHED", local_ip="10.0.0.2", external=True):
    return Connection(protocol="tcp", family="ipv4", local_ip=local_ip, local_port=5000, remote_ip=remote_ip,
                      remote_port=443, state=state, pid=7, process_name="x", is_external=external)


def test_a_sample_counts_connections_ports_and_findings():
    state = SystemState()
    state.update(connections=[connection("203.0.113.9"), connection("10.0.0.9", external=False),
                              connection(None, state="LISTEN", local_ip="0.0.0.0", external=False)])
    recorder = MetricsRecorder(state, TrafficLedger())
    recorder.sample()
    [sample] = recorder.samples()
    assert (sample.external_connections, sample.network_listeners) == (1, 1)
    assert sample.rate_out == 0.0


def test_history_is_capped_to_half_an_hour():
    recorder = MetricsRecorder(SystemState(), TrafficLedger())
    for _ in range(1000):
        recorder.sample()
    assert len(recorder.samples()) == 900
