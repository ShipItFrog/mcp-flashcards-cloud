"""The deployable app: settings checked before anything starts, the MCP endpoint
answering only what it must, and server limits suited to free-tier hosting.

Settings come from environment variables. None of them is a secret: the server
only checks tokens with the identity provider's public keys.

  FLASHCARDS_ISSUER        the identity provider's issuer, copied exactly from its metadata
  FLASHCARDS_JWKS_URL      where the provider publishes its public signing keys (jwks_uri);
                           must be on the issuer's host
  FLASHCARDS_RESOURCE_URL  this server's MCP URL, exactly as users enter it in Claude and as
                           registered with the provider, e.g. https://example.onrender.com/mcp
  FLASHCARDS_SCOPES        optional: scopes every token must carry, e.g. "flashcards"
  FLASHCARDS_DB            optional: SQLite file (default data/cards.db)
  HOST, PORT               optional: where to listen (default 127.0.0.1 and 8000;
                           0.0.0.0 on Render, which sets RENDER=true)
  LOG_LEVEL                optional: DEBUG, INFO (default), WARNING or ERROR
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, ValidationError
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .server import create_server
from .store import SqliteCardStore
from .verifier import USER_AGENT, JwtTokenVerifier

logger = logging.getLogger(__name__)

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
# Sign-in and refresh scopes belong to the identity provider, not to this server.
# Claude adds offline_access itself when the provider offers it.
NOT_RESOURCE_SCOPES = {"offline_access", "openid", "profile", "email"}
SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")  # RFC 6749 scope-token
# Render's edge reuses connections to the app for up to 75 s; closing them sooner causes 502s.
KEEP_ALIVE_SECONDS = 120
# Most simultaneous connections; beyond this new ones get 503 instead of the instance
# running out of memory.
MAX_CONNECTIONS = 400


class ConfigError(SystemExit):
    """Missing or invalid settings. Stops the server with a readable message."""


class _Url(BaseModel):
    # Same parsing as the SDK's AuthSettings, so "standard form" here means what the
    # metadata will show.
    model_config = ConfigDict(url_preserve_empty_path=True)
    url: AnyHttpUrl


@dataclass(frozen=True)
class Settings:
    issuer: str
    jwks_url: str
    resource_url: str
    scopes: list[str]
    db_path: Path
    host: str
    port: int
    log_level: str
    on_render: bool


def _url(env: Mapping[str, str], name: str, errors: list[str]) -> str:
    """A URL in its standard form: https (plain http only for this machine), lower-case
    scheme and host, no default port, no user name, query or fragment. The token and
    Host checks compare strings exactly, so any other spelling would refuse everyone
    while the metadata (which the SDK normalizes) looked fine."""
    value = env.get(name, "")
    if not value.strip():
        errors.append(f"{name} is missing")
        return value
    if any(c.isspace() or not c.isprintable() for c in value):
        errors.append(f"{name} must not contain spaces or control characters: {value!r}")
        return value
    try:
        standard = str(_Url(url=value).url)
    except ValidationError:
        errors.append(f"{name} is not a valid http(s) URL: {value!r}")
        return value
    parts = urlsplit(value)
    if parts.username or parts.password:
        errors.append(f"{name} must not contain a user name or password")
    elif standard != value:
        errors.append(f"{name} must be written as {standard!r} (lower-case, no default port), not {value!r}")
    if parts.query or parts.fragment:
        errors.append(f"{name} must not have a query or fragment: {value!r}")
    if parts.scheme == "http" and parts.hostname not in LOCAL_HOSTS:
        errors.append(f"{name} must use https (plain http only for localhost): {value!r}")
    return value


def _same_host(url: str, other: str) -> bool:
    return urlsplit(url).hostname == urlsplit(other).hostname


def load_settings(env: Mapping[str, str]) -> Settings:
    """Read and check every setting, reporting all problems at once."""
    errors: list[str] = []
    issuer = _url(env, "FLASHCARDS_ISSUER", errors)
    jwks_url = _url(env, "FLASHCARDS_JWKS_URL", errors)
    resource_url = _url(env, "FLASHCARDS_RESOURCE_URL", errors)

    path = urlsplit(resource_url).path
    if resource_url.strip() and (path in ("", "/") or path.endswith("/")):
        errors.append(f"FLASHCARDS_RESOURCE_URL needs a path such as /mcp, with no trailing slash: {resource_url!r}")
    # Every key published at the JWKS URL is trusted, so it must belong to the issuer.
    if issuer.strip() and jwks_url.strip() and not _same_host(jwks_url, issuer):
        errors.append(f"FLASHCARDS_JWKS_URL must be on the issuer's host ({urlsplit(issuer).hostname}): {jwks_url!r}")

    scopes = [s for s in re.split(r"[\s,]+", env.get("FLASHCARDS_SCOPES", "")) if s]
    for s in scopes:
        if s in NOT_RESOURCE_SCOPES:
            errors.append(
                f"FLASHCARDS_SCOPES must not include {s!r}: it is a sign-in scope, not this server's "
                "(Claude asks for offline_access by itself when the provider offers it)"
            )
        elif not SCOPE_TOKEN.fullmatch(s):
            errors.append(f"FLASHCARDS_SCOPES has an invalid scope name: {s!r}")

    db = env.get("FLASHCARDS_DB", "data/cards.db").strip()
    if not db:
        errors.append("FLASHCARDS_DB is empty")

    on_render = env.get("RENDER") == "true"
    host = env.get("HOST", "").strip() or ("0.0.0.0" if on_render else "127.0.0.1")
    port_text = env.get("PORT", "8000").strip()
    port = int(port_text) if re.fullmatch(r"[0-9]{1,5}", port_text) else 0
    if not 1 <= port <= 65535:
        errors.append(f"PORT must be a number from 1 to 65535, got {port_text!r}")
    log_level = env.get("LOG_LEVEL", "INFO").strip().upper()
    if log_level not in LOG_LEVELS:
        errors.append(f"LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}, got {log_level!r}")

    if errors:
        raise ConfigError("Invalid settings (see flashcards_cloud/app.py):\n- " + "\n- ".join(errors))
    return Settings(
        issuer=issuer,
        jwks_url=jwks_url,
        resource_url=resource_url,
        scopes=scopes,
        db_path=Path(db),
        host=host,
        port=port,
        log_level=log_level,
        on_render=on_render,
    )


def check_provider(settings: Settings, *, timeout: float = 5) -> None:
    """Compare the settings with the identity provider's published metadata. A
    mismatch stops the server; an unreachable provider only warns, so an outage at
    the provider can't block a restart.

    Catches the easy mistakes: a mistyped issuer (Descope then serves a different,
    project-wide document instead of an error) or a JWKS URL that isn't the provider's.
    """
    parts = urlsplit(settings.issuer)
    origin, path = f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")
    # The order MCP clients use (RFC 8414 path insertion, then OIDC insertion and appending).
    candidates = dict.fromkeys(
        [
            f"{origin}/.well-known/oauth-authorization-server{path}",
            f"{origin}/.well-known/openid-configuration{path}",
            f"{origin}{path}/.well-known/openid-configuration",
        ]
    )
    empty_at = None
    for url in candidates:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                metadata = json.load(response)
        except (OSError, ValueError, http.client.HTTPException):  # unreachable, HTTP error or not JSON
            continue
        if not isinstance(metadata, dict) or "issuer" not in metadata:
            empty_at = empty_at or url
            continue
        problems = []
        if metadata["issuer"] != settings.issuer:
            problems.append(f"its issuer is {metadata['issuer']!r} but FLASHCARDS_ISSUER is {settings.issuer!r}")
        if metadata.get("jwks_uri") != settings.jwks_url:
            problems.append(f"its jwks_uri is {metadata.get('jwks_uri')!r} but FLASHCARDS_JWKS_URL is {settings.jwks_url!r}")
        if problems:
            raise ConfigError(f"The identity provider's metadata at {url} does not match the settings: " + "; ".join(problems))
        logger.info("The identity provider's metadata at %s matches the settings", url)
        return
    if empty_at:
        raise ConfigError(
            f"No authorization server metadata for FLASHCARDS_ISSUER={settings.issuer!r} "
            f"(empty document at {empty_at}). Copy the issuer exactly from the provider."
        )
    logger.warning("Could not reach the identity provider's metadata to double-check the settings; starting anyway")


class McpEndpointGuard:
    """In front of the MCP endpoint.

    Only POST is served. Without sessions, a 2025-era client's GET would open an event
    stream that can never carry a message and never ends; held open by the thousand,
    such streams would exhaust the instance's memory. Both protocol generations allow
    405 here, and Claude's clients treat it as "no stream offered".

    401 and 403 challenges also name the scopes this server needs (the MCP spec says
    SHOULD), so a client asks for the right scope instead of retrying.
    """

    def __init__(self, app: ASGIApp, *, path: str, scopes: list[str]) -> None:
        self.app = app
        self.path = path
        self.scope_param = f', scope="{" ".join(scopes)}"'.encode() if scopes else b""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != self.path:
            await self.app(scope, receive, send)
            return
        if scope["method"] != "POST":
            response = PlainTextResponse("Method Not Allowed", status_code=405, headers={"Allow": "POST"})
            await response(scope, receive, send)
            return
        if not self.scope_param:
            await self.app(scope, receive, send)
            return

        async def send_with_scope(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] in (401, 403):
                headers = [
                    (name, value + self.scope_param if name.lower() == b"www-authenticate" else value)
                    for name, value in message["headers"]
                ]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_scope)


def build_app(settings: Settings) -> Starlette:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    if settings.db_path.exists():
        logger.info("Opened existing database %s", settings.db_path)
    else:
        logger.warning(
            "Created a NEW empty database at %s. If you expected existing cards, check FLASHCARDS_DB "
            "and whether this disk survives restarts.",
            settings.db_path,
        )
    mcp = create_server(
        store=SqliteCardStore(settings.db_path),
        token_verifier=JwtTokenVerifier(issuer=settings.issuer, audience=settings.resource_url, jwks_url=settings.jwks_url),
        issuer_url=settings.issuer,
        resource_url=settings.resource_url,
        required_scopes=settings.scopes,
    )
    resource = urlsplit(settings.resource_url)
    app = mcp.streamable_http_app(
        streamable_http_path=resource.path,
        # No per-connection sessions: every request carries its own token and is
        # checked on its own, a restart loses nothing, and no session cap to exhaust.
        stateless_http=True,
        # Only answer requests addressed to this server's own name (DNS rebinding protection).
        transport_security=TransportSecuritySettings(
            allowed_hosts=[resource.netloc],
            allowed_origins=[f"{resource.scheme}://{resource.netloc}"],
        ),
    )
    # /mcp/ would otherwise redirect to /mcp - behind Render's proxy, to plain http://.
    app.router.redirect_slashes = False
    # The SDK serves the protected resource metadata only at the path-specific URL;
    # Anthropic recommends the root URL as well.
    specific = f"/.well-known/oauth-protected-resource{resource.path}"
    metadata_route = next(r for r in app.router.routes if isinstance(r, Route) and r.path == specific)
    app.router.routes.append(
        Route("/.well-known/oauth-protected-resource", endpoint=metadata_route.endpoint, methods=["GET", "OPTIONS"])
    )
    app.add_middleware(McpEndpointGuard, path=resource.path, scopes=settings.scopes)
    return app


def server_options(settings: Settings) -> dict[str, Any]:
    """uvicorn settings. log_config=None keeps uvicorn's lines in the app's log format."""
    options: dict[str, Any] = {
        "host": settings.host,
        "port": settings.port,
        "timeout_keep_alive": KEEP_ALIVE_SECONDS,
        "limit_concurrency": MAX_CONNECTIONS,
        "log_config": None,
    }
    if settings.on_render:
        # Only Render's edge can reach the container, so its X-Forwarded-* headers can be
        # trusted. They are used for logs only, never for access decisions.
        options["forwarded_allow_ips"] = "*"
    return options
