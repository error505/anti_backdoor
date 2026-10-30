import re
from typing import Literal

from pydantic import BaseModel

DEFAULT_BASE_URL = "https://api.flockion.com"
# The Flockion docs publish the endpoint and the "flk_" key format but not the auth header or body
# schema, so these defaults are assumptions that the UI lets you change and the test ping verifies.
DEFAULT_AUTH_HEADER = "Authorization"
DEFAULT_AUTH_SCHEME = "Bearer"
DEFAULT_BODY_FIELD = "message"

AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")
BODY_FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

SendMode = Literal["findings", "full"]


class FlockionSettingsView(BaseModel):
    """What the UI may see: never the key itself."""
    agent_id: str
    base_url: str
    auth_header: str
    auth_scheme: str
    body_field: str
    has_stored_key: bool
    key_hint: str | None


class FlockionResult(BaseModel):
    status_code: int
    ok: bool
    url: str
    sent_chars: int
    response_text: str
