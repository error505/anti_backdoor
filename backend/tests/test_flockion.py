"""Tests against fake Flockion servers that follow the protocol used by the Flockion VS Code extension."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from websockets.sync.server import serve

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError
from backdoor_watch.domain.flockion import parse_endpoint
from backdoor_watch.flockion.client import FlockionClient
from backdoor_watch.flockion.settings_store import FlockionConnection, FlockionSettingsStore

KEY = "flk_" + "k" * 24
ENDPOINT = "https://api.flockion.com/api/v1/api-access/agent/abc-123/run"


def test_parses_the_runtime_url_like_the_extension():
    endpoint = parse_endpoint(ENDPOINT)
    assert (endpoint.asset_type, endpoint.asset_id) == ("agent", "abc-123")
    assert endpoint.operation_url("editor-models") == "https://api.flockion.com/api/v1/api-access/agent/abc-123/editor-models"
    assert endpoint.websocket_url() == "wss://api.flockion.com/api/v1/api-access/agent/abc-123/editor"


@pytest.mark.parametrize("url", [
    "http://api.flockion.com/api/v1/api-access/agent/a/run",     # key must not travel over plain http
    "https://flockion.com/docs/vscode-extension",
    "https://api.flockion.com/api/v1/api-access/agent/a/run?x=1",
    "https://user:pw@api.flockion.com/api/v1/api-access/agent/a/run",
    "https://api.flockion.com/api/v1/api-access/agent/a_b/run",  # ids allow letters, digits and hyphens only
])
def test_rejects_unsafe_or_wrong_endpoints(url):
    with pytest.raises(ActionRefusedError):
        parse_endpoint(url)


def test_http_is_allowed_on_localhost_only():
    assert parse_endpoint("http://127.0.0.1:8000/api/v1/api-access/team/t1/run").websocket_url().startswith("ws://127.0.0.1:8000")


def test_key_is_encrypted_validated_and_hidden(tmp_path):
    store = FlockionSettingsStore(tmp_path / "f.json")
    store.save(ENDPOINT, KEY)
    assert KEY not in (tmp_path / "f.json").read_text(encoding="utf-8")
    view = store.view()
    assert view.has_stored_key and view.key_hint == "…kkkk" and KEY not in view.model_dump_json()
    with pytest.raises(ActionRefusedError):
        store.save(ENDPOINT, "sk-not-a-flockion-key")


class _ModelsHandler(BaseHTTPRequestHandler):
    seen_auth = None

    def do_GET(self):  # noqa: N802
        _ModelsHandler.seen_auth = self.headers.get("Authorization")
        ok = _ModelsHandler.seen_auth == f"Bearer {KEY}"
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"items": [{"provider": "p"}], "assetName": "SOC Agent"} if ok
                                    else {"detail": "Bearer API key required"}).encode())

    def log_message(self, *args):
        pass


def _local(port: int) -> str:
    return f"http://127.0.0.1:{port}/api/v1/api-access/agent/abc-123/run"


def test_check_sends_bearer_key_and_reads_the_agent_name():
    server = HTTPServer(("127.0.0.1", 0), _ModelsHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ok = FlockionClient().check(FlockionConnection(_local(server.server_port), KEY))
    bad = FlockionClient().check(FlockionConnection(_local(server.server_port), "flk_" + "x" * 24))
    server.shutdown()
    assert (ok.ok, ok.asset_name, ok.model_count) == (True, "SOC Agent", 1)
    assert bad.ok is False and "Bearer API key required" in bad.detail


def test_run_follows_the_websocket_protocol_and_denies_every_tool_request():
    seen: dict = {}

    def handler(socket):
        start = json.loads(socket.recv())
        seen["start"] = start
        socket.send(json.dumps({"kind": "ready"}))
        socket.send(json.dumps({"kind": "approval_required", "actionId": "a1", "action": {"action": "run"}}))
        seen["approval"] = json.loads(socket.recv())
        socket.send(json.dumps({"kind": "execute_tool", "actionId": "a2", "action": {"action": "read"}}))
        seen["tool"] = json.loads(socket.recv())
        socket.send(json.dumps({"kind": "done", "result": {"status": "succeeded", "output": "VERDICT: CLEAR",
                                                           "spend": {"costUsd": 0.12, "totalTokens": 3400}}}))

    with serve(handler, "127.0.0.1", 0) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.socket.getsockname()[1]
        result = FlockionClient().run(FlockionConnection(_local(port), KEY), "snapshot")
    assert seen["start"]["kind"] == "start" and seen["start"]["token"] == KEY
    assert (seen["start"]["mode"], seen["start"]["permissionMode"], seen["start"]["message"]) == ("ask", "review", "snapshot")
    assert seen["start"]["budgetCapUsd"] > 0
    assert seen["approval"] == {"kind": "approval", "actionId": "a1", "approved": False}
    assert seen["tool"]["kind"] == "tool_result" and seen["tool"]["result"]["ok"] is False
    assert (result.ok, result.output, result.cost_usd, result.denied_tool_requests) == (True, "VERDICT: CLEAR", 0.12, 2)


def test_run_surfaces_server_errors():
    def handler(socket):
        socket.recv()
        socket.send(json.dumps({"kind": "error", "message": "Runtime admission denied"}))

    with serve(handler, "127.0.0.1", 0) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        with pytest.raises(ActionFailedError, match="Runtime admission denied"):
            FlockionClient().run(FlockionConnection(_local(server.socket.getsockname()[1]), KEY), "x")


def test_client_refuses_without_a_key():
    with pytest.raises(ActionRefusedError):
        FlockionClient().run(FlockionConnection(ENDPOINT, None), "hello")
