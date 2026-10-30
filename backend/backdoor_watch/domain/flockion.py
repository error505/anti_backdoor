"""Flockion runtime connection. Protocol taken from the Flockion VS Code extension (agent-hub/extensions).

Verify:  GET  {api-access}/{agent|team}/{id}/editor-models   with  Authorization: Bearer flk_...
Run:     WSS  {api-access}/{agent|team}/{id}/editor          first frame {"kind": "start", "token": ...}
"""

import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel

from backdoor_watch.domain.errors import ActionRefusedError

DEFAULT_ENDPOINT = "https://api.flockion.com/api/v1/api-access/agent/AGENT_ID/run"
KEY_PATTERN = re.compile(r"^flk_[A-Za-z0-9_-]{20,}$")
ENDPOINT_PATH = re.compile(r"^(.*/api-access)/(agent|team)/([a-zA-Z0-9-]{1,36})/run/?$")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}

SendMode = Literal["findings", "full"]
AssetType = Literal["agent", "team"]


class FlockionEndpoint(BaseModel, frozen=True):
    api_access_url: str
    asset_type: AssetType
    asset_id: str

    @property
    def run_url(self) -> str:
        return f"{self.api_access_url}/{self.asset_type}/{self.asset_id}/run"

    def operation_url(self, operation: str) -> str:
        return f"{self.api_access_url}/{self.asset_type}/{self.asset_id}/{operation}"

    def websocket_url(self) -> str:
        url = self.operation_url("editor")
        return "wss://" + url[len("https://"):] if url.startswith("https://") else "ws://" + url[len("http://"):]


def parse_endpoint(value: str) -> FlockionEndpoint:
    """Same rules as the extension: https (or http on localhost), no credentials, query or fragment."""
    parsed = urlparse(value.strip())
    local = parsed.hostname in _LOCAL_HOSTS
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ActionRefusedError("Use an endpoint without credentials, query parameters or fragments")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ActionRefusedError("Use HTTPS (HTTP is allowed only on localhost)")
    match = ENDPOINT_PATH.match(parsed.path)
    if not parsed.hostname or not match:
        raise ActionRefusedError("Use the agent runtime URL ending in /api-access/{agent|team}/{id}/run")
    base = f"{parsed.scheme}://{parsed.netloc}{match.group(1)}"
    return FlockionEndpoint(api_access_url=base, asset_type=match.group(2), asset_id=match.group(3))


class FlockionSettingsView(BaseModel):
    """What the UI may see: never the key itself."""
    endpoint: str
    has_stored_key: bool
    key_hint: str | None


class FlockionCheck(BaseModel):
    ok: bool
    asset_name: str | None
    model_count: int
    detail: str


class FlockionResult(BaseModel):
    ok: bool
    status: str
    output: str
    sent_chars: int
    cost_usd: float | None = None
    total_tokens: int | None = None
    denied_tool_requests: int = 0
