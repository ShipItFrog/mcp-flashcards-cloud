"""Real access-token checks: a JWT from the identity provider, verified locally.

The provider signs each access token. This server checks it on its own, using the
provider's published public keys (its JWKS), so a request needs no call to the
provider. A token is accepted only if:

- its signature is valid, made with one of the provider's keys. The allowed
  algorithms are fixed here and never taken from the token (RFC 8725);
- its issuer (`iss`) is exactly the configured one;
- its audience (`aud`) includes this server's URL, so a token the same provider
  issued for some other server is refused (RFC 8707);
- it has not expired (`exp` is required) and is not dated in the future;
- it names a user (`sub`), which identity.py uses as the data owner, and has no
  `dsub` claim (Descope's sign that a token template replaced `sub`);
- if it names its kind (`token_type`), that is `access_token`, so a token that
  says it is a refresh or ID token can't stand in for one. Descope's access tokens
  carry the claim; tokens without it are judged by the other checks only;
- it is short-lived: valid for at most a day (Descope's last 10 minutes).

Anything else returns None, and the SDK answers 401. Tokens are never logged.
The server holds no secrets for this: the issuer, key URL and its own URL are public.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import anyio
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier

from . import __version__

logger = logging.getLogger(__name__)

# Asymmetric algorithms only. Descope's metadata lists only RS256, but a project run
# by Descope itself publishes ES384 keys. PyJWT also requires the token's algorithm
# to be the one bound to the matching key, so a token can't pick a weaker one.
ALGORITHMS = ["RS256", "ES384"]
REQUIRED_CLAIMS = ["iss", "sub", "aud", "exp"]
# Tolerated clock difference between this server and the provider.
LEEWAY_SECONDS = 30
# The only token_type accepted when a token has the claim, even if it is null or empty
# (Descope's access tokens carry it).
ACCESS_TOKEN_TYPE = "access_token"
# Longest validity accepted: from iat to exp, or from now to exp when there is no
# iat. A token valid for longer is not a short-lived access token, and would stay
# usable that long if it leaked.
MAX_LIFETIME_SECONDS = 24 * 60 * 60
# Fetched keys are reused for this long. While the provider is reachable, a token
# naming a key id we don't have triggers at most one early re-fetch per 30 seconds
# (PyJWT's cooldown, counted from the last successful fetch), so made-up key ids
# can't make this server flood the provider. Known limit: while the key endpoint is
# failing, PyJWT keeps no stale keys and has no back-off, so each request retries.
KEYS_CACHE_SECONDS = 300
KEYS_FETCH_TIMEOUT_SECONDS = 5
# Descope's key endpoint refuses urllib's default User-Agent with 403, so send our own.
USER_AGENT = f"mcp-flashcards-cloud/{__version__}"
# Start of PyJWT's message for a token whose key id isn't published (a token problem,
# unlike its other key errors, which mean the key endpoint sent unusable data).
UNKNOWN_KEY_ID = "Unable to find a signing key"


def _scopes(claims: dict[str, Any]) -> list[str]:
    """`scope` is a space-separated string (RFC 9068); a list is accepted too."""
    scope = claims.get("scope")
    if isinstance(scope, str):
        return scope.split()
    if isinstance(scope, list):
        return [s for s in scope if isinstance(s, str)]
    return []


def _kind_problem(claims: dict[str, Any]) -> str:
    """Why these claims don't describe a short-lived access token, or "" if they do."""
    if "token_type" in claims and claims["token_type"] != ACCESS_TOKEN_TYPE:
        return f"its token_type is {str(claims['token_type'])[:40]!r}, not {ACCESS_TOKEN_TYPE!r}"
    exp, iat = claims["exp"], claims.get("iat")
    if iat is not None:
        lifetime = exp - iat
    else:
        # Without iat, count from now, allowing for the provider's clock running ahead.
        lifetime = exp - time.time() - LEEWAY_SECONDS
    if lifetime > MAX_LIFETIME_SECONDS:
        return f"it is valid for {int(lifetime)} seconds, more than the {MAX_LIFETIME_SECONDS} allowed"
    return ""


def _claimed(token: str) -> dict[str, Any]:
    """The token's claims without any checks - only for explaining a rejection."""
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}


class JwtTokenVerifier(TokenVerifier):
    def __init__(self, *, issuer: str, audience: str, jwks_url: str) -> None:
        self.issuer = issuer
        self.audience = audience
        self._keys = jwt.PyJWKClient(
            jwks_url,
            lifespan=KEYS_CACHE_SECONDS,
            timeout=KEYS_FETCH_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # Fetching keys is blocking network I/O, so it runs in a worker thread.
            claims = await anyio.to_thread.run_sync(self._decode, token)
        except jwt.PyJWKClientConnectionError as e:
            logger.warning("Could not fetch the identity provider's signing keys: %s", e)
            return None
        except (jwt.PyJWKClientError, jwt.PyJWKSetError) as e:
            if str(e).startswith(UNKNOWN_KEY_ID):
                logger.info("Rejected an access token: no published key matches its key id")
            else:
                logger.warning("The identity provider's key endpoint sent unusable keys: %s: %.200r", type(e).__name__, str(e))
            return None
        except (jwt.InvalidIssuerError, jwt.InvalidAudienceError) as e:
            # The signature was valid, so this is a real token from the provider,
            # issued for something else: usually a configuration mismatch. Say what
            # it claimed (never the token itself) so the mismatch is easy to spot.
            claimed = _claimed(token)
            logger.info(
                "Rejected an access token: %s. It claims iss=%.200r aud=%.200r; this server expects iss=%r aud=%r",
                type(e).__name__, claimed.get("iss"), claimed.get("aud"), self.issuer, self.audience,
            )
            return None
        except jwt.PyJWTError as e:
            logger.info("Rejected an access token: %s: %.200r", type(e).__name__, str(e))
            return None
        except Exception as e:
            # Fail closed: an unexpected error (in practice, the key endpoint sending
            # something that isn't JSON) is a rejected token, not a crash. One line, no
            # traceback: it can repeat on every request while the endpoint is broken.
            logger.warning("Could not check an access token: %s: %.200r", type(e).__name__, str(e))
            return None
        if "dsub" in claims:
            # Descope moves the user ID to `dsub` when a token template overrides `sub`;
            # `sub` may then no longer identify the user, and it is the data owner here.
            logger.warning(
                "Rejected an access token with a 'dsub' claim: its 'sub' may not be the user's ID. "
                "Turn off 'override subject claim' in the token template this server's tokens use."
            )
            return None
        if not claims["sub"]:
            return None
        try:
            problem = _kind_problem(claims)
        except (TypeError, ValueError, OverflowError):
            # PyJWT accepts an exp or iat that int() can read, such as a numeric string,
            # or a number too large for a float. Fail closed instead of answering 500.
            problem = "its exp or iat is not a plain number"
        if problem:
            logger.info("Rejected an access token: %s", problem)
            return None
        return AccessToken(
            token=token,
            client_id=str(claims.get("client_id") or claims.get("azp") or ""),
            scopes=_scopes(claims),
            expires_at=int(claims["exp"]),
            # The audience check passed, so this token was issued for this server.
            resource=self.audience,
            subject=claims["sub"],
            claims={"iss": claims["iss"], "sub": claims["sub"]},
        )

    def _decode(self, token: str) -> dict[str, Any]:
        key = self._keys.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            issuer=self.issuer,
            audience=self.audience,
            leeway=LEEWAY_SECONDS,
            options={"require": REQUIRED_CLAIMS},
        )
