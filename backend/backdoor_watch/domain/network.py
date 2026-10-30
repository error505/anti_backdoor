from typing import Literal

from pydantic import BaseModel, computed_field

from backdoor_watch.domain.addresses import ALL_INTERFACES, is_loopback_address

ConnectionKey = tuple[str, str, int, str | None, int | None]


class Connection(BaseModel):
    protocol: Literal["tcp", "udp"]
    family: Literal["ipv4", "ipv6"]
    local_ip: str
    local_port: int
    remote_ip: str | None
    remote_port: int | None
    state: str
    pid: int | None
    process_name: str | None
    remote_host: str | None = None
    is_external: bool = False
    bytes_out: int | None = None
    bytes_in: int | None = None

    def key(self) -> ConnectionKey:
        return (self.protocol, self.local_ip, self.local_port, self.remote_ip, self.remote_port)

    @computed_field
    @property
    def is_listener(self) -> bool:
        return self.state == "LISTEN" or (self.protocol == "udp" and self.remote_ip is None)

    @computed_field
    @property
    def exposure(self) -> Literal["network", "local"]:
        """Whether other machines can reach this socket, which matters for backdoor listeners."""
        if self.local_ip in ALL_INTERFACES or not is_loopback_address(self.local_ip):
            return "network"
        return "local"


class ProcessTraffic(BaseModel):
    pid: int
    process_name: str
    bytes_out: int
    bytes_in: int
    rate_out: float
    rate_in: float
    remotes: list[str]


class RemoteTraffic(BaseModel):
    remote_ip: str
    remote_host: str | None
    bytes_out: int
    bytes_in: int
    processes: list[str]
