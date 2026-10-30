"""Optional live packet inspection using scapy + Npcap.

Only outbound payloads are inspected and each flow is sampled at most a few
times, to keep CPU use low and the log readable.
"""

import logging
import socket
from collections.abc import Callable
from types import SimpleNamespace

import psutil

from backdoor_watch.capture.capture_log import CaptureLog
from backdoor_watch.capture.packet_parsers import (is_tls_record, parse_http_request, parse_tls_sni,
                                                   printable_preview)
from backdoor_watch.collectors.dns_names import DnsNameResolver
from backdoor_watch.domain.addresses import is_public_address, strip_scope
from backdoor_watch.domain.errors import CaptureUnavailableError
from backdoor_watch.domain.security_tools import CaptureProtocol, CaptureRecord, CaptureStatus

logger = logging.getLogger(__name__)

OwnerLookup = Callable[[str, int], tuple[int, str] | None]
_MAX_RECORDS_PER_FLOW = 3
_MAX_TRACKED_FLOWS = 50_000
_NPCAP_HINT = "Npcap is not installed. Get it from https://npcap.com, then restart Backdoor Watch."


def _decode(name) -> str:
    return (name.decode("utf-8", "replace") if isinstance(name, bytes) else str(name)).rstrip(".")


def _dns_answers(dns) -> list:
    answers = dns.an
    if answers is None:
        return []
    return answers if isinstance(answers, list) else [answers[i] for i in range(dns.ancount)]


class PacketSniffer:
    def __init__(self, log: CaptureLog, dns: DnsNameResolver, owner_lookup: OwnerLookup) -> None:
        self._log = log
        self._dns = dns
        self._owner_lookup = owner_lookup
        self._sniffer = None
        self._layers = SimpleNamespace()
        self._local_ips: set[str] = set()
        self._flow_counts: dict[tuple, int] = {}

    def status(self) -> CaptureStatus:
        running = bool(self._sniffer and getattr(self._sniffer, "running", False))
        error = getattr(self._sniffer, "exception", None) if self._sniffer else None
        if error:
            return CaptureStatus(running=False, available=False, message=f"Capture stopped: {error}")
        return CaptureStatus(running=running, available=True,
                             message="Capturing outbound traffic" if running else "Idle")

    def start(self) -> None:
        if self.status().running:
            return
        async_sniffer = self._load_scapy()
        self._local_ips = {strip_scope(a.address) for addrs in psutil.net_if_addrs().values()
                           for a in addrs if a.family in (socket.AF_INET, socket.AF_INET6)}
        sources = " or ".join(f"src host {ip}" for ip in sorted(self._local_ips))
        self._sniffer = async_sniffer(filter=f"udp port 53 or (tcp and ({sources}))",
                                      prn=self._safe_handle, store=False)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer and getattr(self._sniffer, "running", False):
            self._sniffer.stop()

    def _load_scapy(self):
        try:
            from scapy.all import DNS, IP, TCP, UDP, AsyncSniffer, IPv6, Raw, conf
        except ImportError as exc:
            raise CaptureUnavailableError("scapy is not installed (pip install scapy)") from exc
        if not conf.use_pcap:
            raise CaptureUnavailableError(_NPCAP_HINT)
        self._layers = SimpleNamespace(DNS=DNS, IP=IP, IPv6=IPv6, TCP=TCP, UDP=UDP, Raw=Raw)
        return AsyncSniffer

    def _safe_handle(self, packet) -> None:
        try:
            self._handle(packet)
        except Exception:  # one malformed packet must not stop the capture thread
            logger.debug("packet_parse_failed", exc_info=True)

    def _handle(self, packet) -> None:
        layers = self._layers
        ip = packet[layers.IP] if packet.haslayer(layers.IP) else (
            packet[layers.IPv6] if packet.haslayer(layers.IPv6) else None)
        if ip is None:
            return
        if packet.haslayer(layers.DNS) and packet.haslayer(layers.UDP):
            self._on_dns(packet[layers.DNS], ip, packet[layers.UDP].sport)
        elif packet.haslayer(layers.TCP) and packet.haslayer(layers.Raw) and ip.src in self._local_ips:
            self._on_outbound_tcp(ip, packet[layers.TCP], bytes(packet[layers.Raw].load))

    def _on_dns(self, dns, ip, source_port: int) -> None:
        if dns.qr == 1:
            for answer in _dns_answers(dns):
                if answer.type in (1, 28):
                    self._dns.record(str(answer.rdata), _decode(answer.rrname))
            return
        if ip.src not in self._local_ips or not dns.qdcount:
            return
        name = _decode(dns.qd[0].qname)
        self._append(CaptureProtocol.DNS, f"DNS lookup: {name}", ip, source_port, 53, "udp", "")

    def _on_outbound_tcp(self, ip, tcp, payload: bytes) -> None:
        flow = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if self._flow_counts.get(flow, 0) >= _MAX_RECORDS_PER_FLOW:
            return
        classified = self._classify(payload, ip.dst)
        if classified is None:
            return
        if len(self._flow_counts) > _MAX_TRACKED_FLOWS:
            self._flow_counts.clear()
        self._flow_counts[flow] = self._flow_counts.get(flow, 0) + 1
        self._append(*classified[:2], ip, tcp.sport, tcp.dport, "tcp", classified[2])

    def _classify(self, payload: bytes, destination: str) -> tuple[CaptureProtocol, str, str] | None:
        sni = parse_tls_sni(payload)
        if sni:
            self._dns.record(destination, sni)
            return CaptureProtocol.TLS, f"TLS connection to {sni} (content encrypted)", ""
        if is_tls_record(payload):
            return None
        http = parse_http_request(payload)
        if http:
            return CaptureProtocol.HTTP, f"PLAINTEXT HTTP: {http[0]}", http[1]
        if not is_public_address(destination):
            return None
        return (CaptureProtocol.PAYLOAD, f"{len(payload)} bytes, unencrypted/unknown protocol",
                printable_preview(payload))

    def _append(self, protocol: CaptureProtocol, summary: str, ip, local_port: int, remote_port: int,
                transport: str, preview: str) -> None:
        owner = self._owner_lookup(transport, local_port)
        self._log.append(CaptureRecord(
            protocol=protocol, summary=summary, local=f"{ip.src}:{local_port}", remote=f"{ip.dst}:{remote_port}",
            remote_host=self._dns.name_for(ip.dst), pid=owner[0] if owner else None,
            process_name=owner[1] if owner else None, preview=preview,
        ))
