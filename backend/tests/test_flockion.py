import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from backdoor_watch.domain.errors import ActionRefusedError
from backdoor_watch.flockion.client import FlockionClient
from backdoor_watch.flockion.settings_store import FlockionConnection, FlockionSettingsStore

SECRET = "flk_test_secret_0123456789"


def _save(store, **overrides):
    values = {"agent_id": "agent_123", "base_url": "https://api.flockion.com", "auth_header": "Authorization",
              "auth_scheme": "Bearer", "body_field": "message", "api_key": SECRET} | overrides
    store.save(**values)


def test_key_is_encrypted_on_disk_and_hidden_from_view(tmp_path):
    store = FlockionSettingsStore(tmp_path / "f.json")
    _save(store)
    assert SECRET not in (tmp_path / "f.json").read_text(encoding="utf-8")
    view = store.view()
    assert view.has_stored_key and view.key_hint == "…6789" and SECRET not in view.model_dump_json()


@pytest.mark.parametrize("override", [
    {"base_url": "http://api.flockion.com"},        # key must never travel over plain http
    {"base_url": "https://api.flockion.com/x?a=1"},
    {"agent_id": "../../etc"},
    {"auth_header": "Bad Header"},
    {"body_field": "1abc"},
])
def test_rejects_unsafe_settings(tmp_path, override):
    with pytest.raises(ActionRefusedError):
        _save(FlockionSettingsStore(tmp_path / "f.json"), **override)


def test_run_url_uses_the_documented_endpoint(tmp_path):
    store = FlockionSettingsStore(tmp_path / "f.json")
    _save(store)
    assert store.connection().run_url() == "https://api.flockion.com/api/v1/api-access/agent/agent_123/run"


class _Recorder(BaseHTTPRequestHandler):
    seen: dict = {}

    def do_POST(self):  # noqa: N802 (http.server naming)
        length = int(self.headers["Content-Length"])
        _Recorder.seen = {"path": self.path, "auth": self.headers["Authorization"],
                          "body": json.loads(self.rfile.read(length))}
        self.send_response(401)
        self.end_headers()
        self.wfile.write(b'{"error":"bad key"}')

    def log_message(self, *args):  # keep test output quiet
        pass


def test_client_posts_json_with_bearer_key_and_returns_error_bodies():
    server = HTTPServer(("127.0.0.1", 0), _Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    connection = FlockionConnection("agent_123", f"http://127.0.0.1:{server.server_port}", "Authorization",
                                    "Bearer", "message", SECRET)
    result = FlockionClient().run_agent(connection, "hello")
    server.shutdown()
    assert _Recorder.seen["path"] == "/api/v1/api-access/agent/agent_123/run"
    assert _Recorder.seen["auth"] == f"Bearer {SECRET}"
    assert _Recorder.seen["body"] == {"message": "hello"}
    assert (result.status_code, result.ok, "bad key" in result.response_text) == (401, False, True)


def test_client_refuses_without_a_key():
    connection = FlockionConnection("agent_123", "https://api.flockion.com", "Authorization", "Bearer", "message", None)
    with pytest.raises(ActionRefusedError):
        FlockionClient().run_agent(connection, "hello")
