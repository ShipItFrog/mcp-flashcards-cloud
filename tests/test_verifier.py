"""The real token verifier, called directly with real signed JWTs. Every rule it
promises (signature, algorithm, issuer, audience, expiry, subject, token type,
lifetime) has a token that breaks exactly that rule and nothing else."""

import logging
import threading
import time
import urllib.error
import urllib.request

import jwt
import pytest
from helpers import ISSUER, RESOURCE, SCOPE
from jwt_helpers import (
    ATTACKER_KEY,
    CLIENT_ID,
    DROP,
    EC_KID,
    KID,
    PROJECT_ID,
    PROVIDER_EC_KEY,
    KeyEndpoint,
    descope_token,
    hmac_signed_with_public_key,
    key_server,
    make_verifier,
    sign,
    unsigned,
)

from flashcards_cloud.verifier import JwtTokenVerifier

pytestmark = pytest.mark.anyio
# The documented limit (README: "valid for at most a day"), written out here rather
# than read from the verifier, so changing the code's limit fails these tests.
DAY = 24 * 60 * 60


async def test_a_valid_token_names_the_user():
    exp = int(time.time()) + 600
    token = await make_verifier().verify_token(sign(exp=exp))
    assert token is not None
    assert token.subject == "alice"
    assert token.claims == {"iss": ISSUER, "sub": "alice"}
    assert token.resource == RESOURCE
    assert token.scopes == [SCOPE]
    assert token.client_id == "test-client"
    assert token.expires_at == exp


async def test_a_token_shaped_like_descopes_is_read_correctly():
    # aud is a list with this server's URL not first, scope holds several scopes and
    # the client ID is in azp: getting any of these wrong would lock out every real
    # user (401 from the SDK's resource check, or 403 for a missing scope).
    token = await make_verifier().verify_token(descope_token())
    assert token is not None
    assert token.subject == "U2alice"
    assert token.resource == RESOURCE
    assert token.scopes == [SCOPE, "offline_access"]
    assert token.client_id == CLIENT_ID


# Built when the test runs, so times are fresh.
REJECTED = {
    "signed-by-another-key": lambda: sign(key=ATTACKER_KEY),
    "no-signature-alg-none": unsigned,
    "hmac-signed-with-the-public-key": hmac_signed_with_public_key,
    "right-key-other-algorithm": lambda: sign(alg="RS512"),
    "algorithm-not-the-one-bound-to-the-key": lambda: sign(key=PROVIDER_EC_KEY, kid=KID, alg="ES384"),
    "unknown-key-id": lambda: sign(kid="some-other-key"),
    "no-key-id": lambda: sign(kid=None),
    "wrong-issuer": lambda: sign(iss="https://evil.example.test"),
    "issuer-with-extra-slash": lambda: sign(iss=ISSUER + "/"),
    "no-issuer": lambda: sign(iss=DROP),
    "issued-for-another-server": lambda: sign(aud="https://other.example.test/mcp"),
    "audience-list-without-this-server": lambda: sign(aud=["https://a.example.test/mcp", "https://b.example.test/mcp"]),
    "audience-is-a-path-under-this-server": lambda: sign(aud=RESOURCE + "/admin"),
    # An ordinary sign-in token from the same project: same keys, aud = project ID.
    "session-token-for-the-project": lambda: sign(aud=PROJECT_ID),
    "no-audience": lambda: sign(aud=DROP),
    "expired": lambda: sign(exp=int(time.time()) - 120),
    "no-expiry": lambda: sign(exp=DROP),
    "not-valid-yet": lambda: sign(nbf=int(time.time()) + 300),
    "issued-in-the-future": lambda: sign(iat=int(time.time()) + 300),
    "no-subject": lambda: sign(sub=DROP),
    "empty-subject": lambda: sign(sub=""),
    "subject-not-a-string": lambda: sign(sub=12345),
    # Descope's sign that a token template replaced sub with something else.
    "subject-overridden-dsub-present": lambda: sign(dsub="U2alice"),
    "custom-subject-shared-by-a-team": lambda: sign(sub="acme", dsub="U2victim"),
    # Other kinds of token from the same provider, with everything else valid.
    "refresh-token": lambda: sign(token_type="refresh_token"),
    "id-token": lambda: sign(token_type="id_token"),
    "token-type-empty": lambda: sign(token_type=""),
    "token-type-null": lambda: sign(token_type=None),
    "valid-for-more-than-a-day": lambda: sign(exp=int(time.time()) + DAY + 60),
    "valid-for-more-than-a-day-no-iat": lambda: sign(iat=DROP, exp=int(time.time()) + DAY + 3600),
    # Long-lived, but close to expiry: the declared lifetime counts, not the time left.
    "issued-over-a-day-ago-still-valid": lambda: (lambda now: sign(iat=now - DAY, exp=now + 600))(int(time.time())),
    # PyJWT accepts an exp that int() can read; the lifetime check must reject it, not crash.
    "expiry-as-a-string": lambda: sign(exp=str(int(time.time()) + 600)),
    "not-a-jwt": lambda: "not-a-jwt",
}


@pytest.mark.parametrize("make_token", REJECTED.values(), ids=REJECTED.keys())
async def test_a_token_breaking_any_rule_is_rejected(make_token):
    assert await make_verifier().verify_token(make_token()) is None


ACCEPTED = {
    "es384-key-like-descopes-own-project": lambda: sign(key=PROVIDER_EC_KEY, kid=EC_KID, alg="ES384"),
    "audience-list-including-this-server": lambda: sign(aud=["https://other.example.test/mcp", RESOURCE]),
    "provider-clock-slightly-ahead": lambda: sign(iat=int(time.time()) + 10),
    "scope-as-a-list": lambda: sign(scope=[SCOPE, "openid"]),
    "token-type-access-token": lambda: sign(token_type="access_token"),
    "valid-for-exactly-a-day": lambda: (lambda now: sign(iat=now, exp=now + DAY))(int(time.time())),
    "no-iat": lambda: sign(iat=DROP),
}


@pytest.mark.parametrize("make_token", ACCEPTED.values(), ids=ACCEPTED.keys())
async def test_legitimate_variations_are_accepted(make_token):
    token = await make_verifier().verify_token(make_token())
    assert token is not None and token.subject == "alice"
    assert SCOPE in token.scopes


async def test_missing_scope_means_no_scopes():
    # Accepted here; the SDK then answers 403 if the server requires a scope.
    token = await make_verifier().verify_token(sign(scope=DROP))
    assert token is not None and token.scopes == []


async def test_keys_are_cached_and_made_up_key_ids_cannot_flood_the_provider():
    endpoint = KeyEndpoint()
    verifier = make_verifier(endpoint)
    for _ in range(20):
        assert await verifier.verify_token(sign()) is not None
    assert endpoint.fetches == 1
    for i in range(50):
        assert await verifier.verify_token(sign(kid=f"made-up-{i}")) is None
    # At most one early re-fetch for an unknown key id; then the cooldown applies.
    assert endpoint.fetches <= 2


async def test_keys_are_fetched_off_the_event_loop():
    # A slow key endpoint must not freeze every other request on this single-process server.
    endpoint = KeyEndpoint()
    assert await make_verifier(endpoint).verify_token(sign()) is not None
    assert endpoint.threads and threading.get_ident() not in endpoint.threads


@pytest.mark.parametrize(
    "endpoint",
    [
        KeyEndpoint(error=jwt.PyJWKClientConnectionError("connection refused")),
        KeyEndpoint(error=ValueError("the key endpoint sent something that isn't JSON")),
        KeyEndpoint(jwks={"keys": []}),
        KeyEndpoint(jwks=["not", "an", "object"]),
    ],
    ids=["unreachable", "not-json", "no-keys", "not-an-object"],
)
async def test_a_broken_key_endpoint_rejects_the_token_with_one_warning(caplog, endpoint):
    # It can repeat on every request while it lasts, so: a WARNING (visible to
    # monitoring, unlike a token rejection) of one line, without a traceback.
    with caplog.at_level(logging.INFO, logger="flashcards_cloud.verifier"):
        assert await make_verifier(endpoint).verify_token(sign()) is None
    [record] = caplog.records
    assert record.levelno == logging.WARNING
    assert record.exc_info is None and "\n" not in record.getMessage()


async def test_an_unknown_key_id_is_a_token_problem_not_a_provider_problem(caplog):
    with caplog.at_level(logging.INFO, logger="flashcards_cloud.verifier"):
        assert await make_verifier().verify_token(sign(kid="made-up")) is None
    assert {r.levelno for r in caplog.records} == {logging.INFO}


async def test_keys_are_fetched_over_real_http_without_pythons_default_user_agent(no_proxy):
    with key_server() as (url, seen):
        # The stand-in really does refuse the default, like Descope's endpoint...
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(url, timeout=5)
        assert refused.value.code == 403
        # ...and the verifier's own fetch still gets the keys.
        verifier = JwtTokenVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=url)
        token = await verifier.verify_token(sign())
    assert token is not None and token.subject == "alice"
    assert not seen[-1].startswith("Python-urllib")


@pytest.mark.parametrize(
    "make_token, claimed",
    [
        (lambda: sign(iss="https://other-idp.example.test/P123"), "https://other-idp.example.test/P123"),
        (lambda: sign(aud="https://other.example.test/mcp"), "https://other.example.test/mcp"),
    ],
    ids=["issuer", "audience"],
)
async def test_a_mismatch_logs_what_the_token_claimed_and_what_was_expected(caplog, make_token, claimed):
    # A validly signed token for the wrong issuer or audience is almost always a
    # configuration mistake, so the log must make the difference visible.
    with caplog.at_level(logging.INFO, logger="flashcards_cloud.verifier"):
        assert await make_verifier().verify_token(make_token()) is None
    assert claimed in caplog.text
    assert f"expects iss={ISSUER!r} aud={RESOURCE!r}" in caplog.text


async def test_tokens_never_appear_in_the_logs(caplog):
    # Every rejection path, including the ones that see genuine, unexpired tokens
    # (an issuer or audience mismatch, the key endpoint failing).
    tokens = [make() for make in REJECTED.values()] + [sign(), descope_token()]
    with caplog.at_level(logging.DEBUG):
        for token in tokens:
            await make_verifier().verify_token(token)
        for endpoint in (
            KeyEndpoint(error=jwt.PyJWKClientConnectionError("connection refused")),
            KeyEndpoint(error=ValueError("garbage")),
            KeyEndpoint(jwks={"keys": []}),
        ):
            await make_verifier(endpoint).verify_token(tokens[-1])
    assert caplog.records
    for token in tokens:
        if token.count(".") == 2:
            assert token not in caplog.text
            signature = token.rsplit(".", 1)[-1]
            assert not signature or signature not in caplog.text  # not even the signature part
