"""Protects the admin-level API from the rest of the machine and from web pages.

This server can kill processes and edit the firewall while running as
administrator, so:
- the Host header must be the loopback address, which defeats DNS rebinding
  from malicious websites;
- every /api call must carry the per-session token, which defeats CSRF and
  other local programs that do not know it.
"""

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

TOKEN_HEADER = "x-auth-token"


class LocalAccessGuard(BaseHTTPMiddleware):
    def __init__(self, app, token: str, port: int, read_only: bool = False) -> None:
        super().__init__(app)
        self._token = token
        self._allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self._read_only = read_only

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.headers.get("host", "") not in self._allowed_hosts:
            return JSONResponse({"detail": "Forbidden host"}, status_code=403)
        if self._read_only and request.method != "GET":
            # Demo data uses fake PIDs that could match real processes, so actions must never run.
            return JSONResponse({"detail": "Demo mode is read-only: actions are disabled"}, status_code=403)
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(supplied, self._token):
                return JSONResponse({"detail": "Missing or invalid session token"}, status_code=401)
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response
