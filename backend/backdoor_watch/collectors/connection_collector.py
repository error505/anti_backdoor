import socket
from collections.abc import Mapping

import psutil

from backdoor_watch.collectors.dns_names import DnsNameResolver
from backdoor_watch.collectors.tcp_traffic_meter import TcpTrafficMeter
from backdoor_watch.domain.addresses import is_public_address
from backdoor_watch.domain.network import Connection


class ConnectionCollector:
    def __init__(self, dns: DnsNameResolver, meter: TcpTrafficMeter) -> None:
        self._dns = dns
        self._meter = meter

    def snapshot(self, process_names: Mapping[int, str]) -> list[Connection]:
        connections = [self._to_model(raw, process_names)
                       for raw in psutil.net_connections(kind="inet")]
        self._meter.forget_except({c.key() for c in connections})
        return connections

    def _to_model(self, raw, process_names: Mapping[int, str]) -> Connection:
        remote_ip = raw.raddr.ip if raw.raddr else None
        connection = Connection(
            protocol="tcp" if raw.type == socket.SOCK_STREAM else "udp",
            family="ipv6" if raw.family == socket.AF_INET6 else "ipv4",
            local_ip=raw.laddr.ip,
            local_port=raw.laddr.port,
            remote_ip=remote_ip,
            remote_port=raw.raddr.port if raw.raddr else None,
            state=raw.status if raw.status != psutil.CONN_NONE else "BOUND",
            pid=raw.pid or None,
            process_name=process_names.get(raw.pid) if raw.pid else None,
            remote_host=self._dns.name_for(remote_ip),
            is_external=is_public_address(remote_ip),
        )
        return self._with_byte_counts(connection)

    def _with_byte_counts(self, connection: Connection) -> Connection:
        if connection.protocol != "tcp" or connection.state != psutil.CONN_ESTABLISHED:
            return connection
        counts = self._meter.read(connection.key(), connection.family == "ipv6")
        if counts is None:
            return connection
        connection.bytes_out, connection.bytes_in = counts
        return connection
