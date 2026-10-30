import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from backdoor_watch.domain.errors import ActionFailedError
from backdoor_watch.domain.ip_intel import IpIntel
from backdoor_watch.ip_intel.hosting_providers import is_cloud_hosting
from backdoor_watch.ip_intel.ip_intel_service import IpIntelService
from backdoor_watch.ip_intel.ip_intel_store import IpIntelStore
from backdoor_watch.ip_intel.ip_providers import IpWhoIsProvider


class CountingProvider:
    name = "fake"

    def __init__(self, failing: bool = False) -> None:
        self.calls: list[str] = []
        self._failing = failing

    def lookup(self, ip: str) -> IpIntel:
        self.calls.append(ip)
        if self._failing:
            raise ActionFailedError("rate limited")
        return IpIntel(ip=ip, country="Germany", country_code="DE", org="Hetzner Online GmbH", asn="AS24940")


def make_service(tmp_path, provider, enabled: bool) -> IpIntelService:
    service = IpIntelService(provider, IpIntelStore(tmp_path / "cache.json"), tmp_path / "settings.json",
                             resolve_reverse=lambda ip: "static.example.net")
    service.set_enabled(enabled)
    return service


def test_nothing_is_sent_until_the_user_opts_in(tmp_path):
    provider = CountingProvider()
    service = make_service(tmp_path, provider, enabled=False)
    assert service.lookup(["8.8.8.8"]) == []
    assert provider.calls == []


def test_only_public_addresses_leave_the_machine(tmp_path):
    provider = CountingProvider()
    service = make_service(tmp_path, provider, enabled=True)
    service.lookup(["192.168.1.5", "127.0.0.1", "10.0.0.2", "8.8.8.8", "8.8.8.8"])
    assert provider.calls == ["8.8.8.8"]


def test_answers_are_cached_between_calls_and_restarts(tmp_path):
    provider = CountingProvider()
    make_service(tmp_path, provider, enabled=True).lookup(["8.8.8.8"])
    restarted = make_service(tmp_path, provider, enabled=False)
    [hit] = restarted.lookup(["8.8.8.8"])
    assert provider.calls == ["8.8.8.8"]
    assert (hit.org, hit.reverse_dns) == ("Hetzner Online GmbH", "static.example.net")


def test_failures_are_reported_but_not_cached(tmp_path):
    provider = CountingProvider(failing=True)
    service = make_service(tmp_path, provider, enabled=True)
    [first] = service.lookup(["8.8.4.4"])
    service.lookup(["8.8.4.4"])
    assert first.error and "rate limited" in first.error
    assert provider.calls == ["8.8.4.4", "8.8.4.4"]


def test_hosting_networks_are_recognised():
    assert is_cloud_hosting("Hetzner Online GmbH")
    assert not is_cloud_hosting("Deutsche Telekom AG")
    assert not is_cloud_hosting(None)


def test_ipwhois_response_is_mapped():
    payload = {"success": True, "country": "United States", "country_code": "US", "region": "California",
               "city": "San Jose", "connection": {"asn": 15169, "org": "Google LLC"}}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        intel = IpWhoIsProvider(f"http://127.0.0.1:{server.server_port}").lookup("8.8.8.8")
    finally:
        server.shutdown()
    assert (intel.country_code, intel.org, intel.asn, intel.cloud_hosting) == ("US", "Google LLC", "AS15169", True)


def test_provider_refusal_raises():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"success": false, "message": "monthly limit"}')

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with pytest.raises(ActionFailedError, match="monthly limit"):
            IpWhoIsProvider(f"http://127.0.0.1:{server.server_port}").lookup("8.8.8.8")
    finally:
        server.shutdown()
