"""Bearer-token protection for the HTTP transport.

The server can write to the athlete's Garmin calendar, so an HTTP deployment
must never run open. ``main()`` calls :func:`require_token` before starting any
HTTP transport (fail-closed: no token -> refuse to start) and wraps the app in
:class:`BearerAuthMiddleware`. stdio never imports this path.

Security notes:
  * Comparison is constant-time (``hmac.compare_digest`` on SHA-256 digests,
    so length is not leaked either).
  * The token is never logged or echoed — errors name the variable only.
  * ``/health`` is the single unauthenticated path (static body, no data) so
    container healthchecks work without distributing the secret.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from collections.abc import Mapping

from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

TOKEN_ENV_VAR = "MCP_AUTH_TOKEN"
HTTP_TRANSPORTS = frozenset({"http", "streamable-http", "sse"})
MIN_TOKEN_LENGTH = 16
HEALTH_PATH = "/health"


class AuthConfigError(RuntimeError):
    """HTTP transport requested without a usable MCP_AUTH_TOKEN."""


def is_http_transport(transport: str) -> bool:
    return transport.strip().lower() in HTTP_TRANSPORTS


def require_token(env: Mapping[str, str] | None = None) -> str:
    """Return the configured bearer token or raise AuthConfigError."""
    env = os.environ if env is None else env
    token = env.get(TOKEN_ENV_VAR, "").strip()
    if not token:
        raise AuthConfigError(
            f"Refusing to start the HTTP transport: {TOKEN_ENV_VAR} is not set. "
            "This server can write to your Garmin calendar and must not run "
            "unauthenticated. Generate a secret "
            "(python -c \"import secrets; print(secrets.token_urlsafe(32))\"), "
            f"set it as {TOKEN_ENV_VAR}, and send it as 'Authorization: Bearer <token>'."
        )
    if len(token) < MIN_TOKEN_LENGTH:
        raise AuthConfigError(
            f"Refusing to start the HTTP transport: {TOKEN_ENV_VAR} is shorter "
            f"than {MIN_TOKEN_LENGTH} characters. Use a long random value."
        )
    return token


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


class BearerAuthMiddleware:
    """Pure-ASGI middleware: 401 unless ``Authorization: Bearer <token>`` matches."""

    def __init__(self, app: ASGIApp, token: str, exempt_paths: tuple[str, ...] = (HEALTH_PATH,)):
        if not token:
            raise AuthConfigError(f"{TOKEN_ENV_VAR} must not be empty")
        self.app = app
        self._expected = _digest(token)
        self._exempt = frozenset(exempt_paths)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)  # lifespan etc.
            return
        if scope["type"] == "http" and scope.get("path") in self._exempt \
                and scope.get("method") in ("GET", "HEAD"):
            await self.app(scope, receive, send)
            return

        if self._authorized(scope):
            await self.app(scope, receive, send)
            return

        # Log path only — never the Authorization header or any part of a token.
        logger.warning("Rejected unauthenticated request: %s %s",
                       scope.get("method", scope["type"]), scope.get("path"))
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        response = JSONResponse(
            {"error": "unauthorized"}, status_code=401,
            headers={"WWW-Authenticate": 'Bearer realm="coach-mcp"'},
        )
        await response(scope, receive, send)

    def _authorized(self, scope: Scope) -> bool:
        header = ""
        for key, value in scope.get("headers", []):
            if key == b"authorization":
                header = value.decode("latin-1")
                break
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not supplied.strip():
            return False
        return hmac.compare_digest(_digest(supplied.strip()), self._expected)


def build_middleware(token: str) -> list[Middleware]:
    return [Middleware(BearerAuthMiddleware, token=token)]
