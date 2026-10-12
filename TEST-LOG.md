# Test log

Everything the README claims should be traceable to this log. Items listed under **Pending** have not been run yet.

## Environment

| Item | Value |
|---|---|
| MCP Python SDK | `mcp` 2.3.0 (`mcp-types` 2.3.0, `httpx2` 2.13.1) |
| PyJWT | 2.15.1 (`cryptography` 50.0.2) |
| Python | 3.14.5 |
| OS | Windows 11 |
| Identity provider (manual tests) | Descope, free plan |

# Step 1: the server and per-user isolation (2026-10-04)

## 1. Per-user isolation (automated)

The tests drive the real ASGI app over HTTP in-process, through the SDK's real auth middleware and a real MCP client. Only the token verifier is fake: it maps test tokens to users.

Every isolation test runs over four transports:
- the 2026-07-28 protocol;
- the 2025-era `initialize` handshake (claude.ai's connector documentation targets the 2025-11-25 specification);
- each of those against a stateless app as well.

The client asserts which protocol it actually negotiated. The SDK's auto mode silently falls back to the old handshake on errors, so without that check, a broken modern path would just test the old one twice.

| What is proven | Test |
|---|---|
| Another user lists and reviews nothing from your deck | `test_isolation.py::test_other_user_sees_none_of_your_cards` |
| Another user can't grade or delete your card by guessing its number, and your card is unchanged | `test_isolation.py::test_other_user_cannot_grade_or_delete_your_card_by_number` |
| Someone else's card returns exactly the same error as a missing card | `test_isolation.py::test_someone_elses_card_looks_exactly_like_a_missing_one` |
| The same person with a different token still sees their deck (identity follows the user, not the token) | `test_isolation.py::test_same_person_with_a_new_token_keeps_their_deck` |
| The same `sub` from a different identity provider is refused, not merged with the real user | `test_isolation.py::test_same_subject_from_another_issuer_is_a_different_person` |
| Card numbers are per user | `test_isolation.py::test_card_numbers_are_per_user` |
| A token with no subject is refused and stores nothing | `test_isolation.py::test_token_without_a_subject_is_refused` |
| No token, an unknown token, or a token issued for another server gets 401 with a pointer to the metadata (both protocol generations) | `test_http_auth.py::test_missing_unknown_or_foreign_tokens_get_401` |
| A token without the required scope gets 403 `insufficient_scope` | `test_http_auth.py::test_token_without_the_required_scope_gets_403` |
| The protected resource metadata names this server and the issuer exactly | `test_http_auth.py::test_protected_resource_metadata_points_at_the_issuer` |
| Every storage method is scoped to its owner | `test_store.py::test_every_method_is_scoped_to_its_owner` |
| 20 simultaneous adds get 20 unique card numbers | `test_store.py::test_concurrent_adds_get_unique_numbers` |
| Abuse limits: card count and total size per user, exact text-length limits, page size, per-user rate limit, out-of-range or non-integer card ids | `test_store.py`, `test_tools.py` |

Result: **67 passed.**

## 2. Do the tests catch real mistakes? (mutation check)

`tests/run_mutations.py` reruns the suite once per deliberately broken variant (`tests/mutations.py`). Each variant is applied at test time; the source files are never changed. A variant counts as caught only if at least one test **fails**. A run that merely errors during setup is reported as invalid.

| Broken variant | Mistake it simulates | Failing tests |
|---|---|---|
| `shared-deck` | Forgot the per-user key | 25 |
| `key-by-client-id` | Keyed data by the OAuth client (the app) instead of the user | 25 |
| `no-subject-check` | Dropped the "token must have a subject" defence | 4 |
| `no-issuer-check` | Trusted any issuer, so one `sub` from two providers became one person | 4 |
| `unscoped-grade` | One storage query forgot its owner filter | 9 |
| `no-audience-check` | Accepted tokens issued for other servers | 2 |
| `review-ignores-time` | Review order ignores when cards were reviewed | 1 |
| `unpaginated-list` | Listing ignores the page size | 2 |
| `topic-not-normalized` | Topic filter only matches the exact spelling | 2 |
| `no-rate-limit` | Rate limit disabled | 1 |

Result: **all 10 caught.** Variants caught by only one or two tests depend on those tests, so those tests must not be removed.

## 3. Code review

A separate review by AI review agents (read-only, checked against the SDK source) found no way for one user to reach another's data. It did raise these issues, all fixed before this log was written:

- **High:** one account could make a single `list_cards` response tens of megabytes, and nothing limited call rates. Fixed with pagination, a total-size quota per user, shorter text limits, and a per-user rate limit.
- **Medium:** three places where tests could pass for the wrong reason. These were a review-order test that couldn't see an ordering bug, an unchecked protocol negotiation, and a mutation verdict that counted setup errors as caught. Fixed, and the first one is now covered by the `review-ignores-time` mutation.
- **Medium:** topic filters weren't normalized like stored topics, and the SDK turned the string `"null"` into "no filter". Fixed with case-insensitive matching and plain-string parameters.
- **Medium:** the storage key relied on the verifier accepting a single issuer. `identity.py` now checks the token's issuer itself.
- **Medium:** synchronous database calls ran on the event loop. They now run in a worker thread, and the concurrent-add test covers them.
- **Low (7):** card-id bounds, invalid Unicode, and several test and config gaps. All fixed.

# Step 2: real sign-in (2026-10-05 to 2026-10-12)

## 4. Real signed tokens (automated)

These tests use real signed JWTs. An RSA key pair and an EC P-384 key pair stand in for the provider's, and only the network fetch of the public keys is replaced. Key matching, caching and every token check are the real PyJWT code with the real verifier's settings.

| What is proven | Test |
|---|---|
| Every rule the verifier promises has a token that breaks exactly that rule, and each is rejected: another key, `alg: none`, HMAC signed with the public key, another algorithm, an algorithm not bound to the key, an unknown or missing key id, a wrong or missing issuer, an audience for another server or for the provider's project, no audience, expired, no expiry, an expiry written as a string, not valid yet, issued in the future, a missing, empty or non-string subject, a `dsub` claim, a `token_type` of refresh, ID, empty or null, valid for more than a day (with or without `iat`, and issued over a day ago but not yet expired) | `test_verifier.py::test_a_token_breaking_any_rule_is_rejected` (33 tokens) |
| Legitimate variations are accepted: ES384 keys, an audience list, the provider's clock slightly ahead, scope as a list, `token_type: access_token`, valid for exactly a day, no `iat` | `test_verifier.py::test_legitimate_variations_are_accepted` |
| A token shaped like Descope's (audience list with this server last, client ID in `azp`, `token_type`), with a second scope added to check splitting, is read correctly | `test_verifier.py::test_a_token_shaped_like_descopes_is_read_correctly` |
| Keys are cached, and made-up key ids cause at most one early re-fetch | `test_verifier.py::test_keys_are_cached_and_made_up_key_ids_cannot_flood_the_provider` |
| Keys are fetched off the event loop | `test_verifier.py::test_keys_are_fetched_off_the_event_loop` |
| A broken key endpoint (unreachable, not JSON, no keys, not an object) rejects the token with one warning line and no traceback | `test_verifier.py::test_a_broken_key_endpoint_rejects_the_token_with_one_warning` |
| Keys are fetched over real HTTP without Python's default User-Agent, which the stand-in refuses with 403 like Descope's endpoint | `test_verifier.py::test_keys_are_fetched_over_real_http_without_pythons_default_user_agent` |
| An issuer or audience mismatch logs what the token claimed and what was expected | `test_verifier.py::test_a_mismatch_logs_what_the_token_claimed_and_what_was_expected` |
| Tokens never appear in the logs, not even their signature | `test_verifier.py::test_tokens_never_appear_in_the_logs` |
| The whole stack with real signed tokens (verifier, SDK auth middleware, MCP, tools, database): signed-in users only see their own cards, on all four transports, with plain and Descope-shaped tokens | `test_jwt_end_to_end.py::test_signed_in_users_only_see_their_own_cards` |
| Bad tokens get 401, a token without the scope gets 403, a valid token gets 200 | `test_jwt_end_to_end.py` |
| The deployable app: the metadata names this server and the issuer exactly; 401 points at the metadata and names the scope; 403 names the scope; a signed token works only for this host and origin; only POST is served (both protocol generations); no subscriptions are offered; no trailing-slash redirect; a new database is announced | `test_app.py` |
| Settings: bad settings stop the server before it starts; all problems are reported at once; plain http only on this machine; keep-alive and connection limits; on Render, listen on all interfaces and trust its proxy | `test_app.py` |
| Provider metadata: matching metadata lets the server start; a different issuer or key URL, or an empty document, stops it; an unreachable provider only warns | `test_app.py` |

Result: **191 passed** (step 1's 67 plus 124).

## 5. Mutation check, step 2 (2026-10-12)

The same runner, with the variants added in step 2. All 39 variants, step 1's included, were rerun on this date.

| Broken variant | Mistake it simulates | Failing tests |
|---|---|---|
| `jwt-signature-not-checked` | Read the token without checking its signature | 17 |
| `jwt-audience-not-checked` | Accepted tokens the provider issued for other servers | 8 |
| `jwt-issuer-not-checked` | Forgot the issuer check | 4 |
| `jwt-expiry-not-checked` | Forgot the expiry check | 3 |
| `jwt-subject-optional` | Accepted a token that doesn't name a user | 24 |
| `jwt-keys-not-cached` | Fetched the keys on every request, so made-up key ids could make it flood the provider | 1 |
| `jwt-default-user-agent` | Fetched keys with Python's default User-Agent, which Descope's endpoint refuses | 1 |
| `jwt-rs256-only` | Allowed RS256 only, though a project run by Descope itself signs with ES384 | 1 |
| `jwt-resource-from-first-aud` | Took the resource from the token's first `aud` entry instead of the configured URL | 6 |
| `jwt-scope-not-split` | Treated the space-separated scope string as one scope | 6 |
| `jwt-client-id-without-azp` | Read the client ID only from `client_id`, which Descope's tokens don't have | 1 |
| `jwt-token-logged-on-mismatch` | Logged the token itself when explaining an issuer or audience mismatch | 1 |
| `jwt-token-in-fetch-error` | Put the token into the key-fetch error, which then lands in the log | 1 |
| `jwt-decode-on-event-loop` | Fetched keys on the event loop, freezing every other request | 1 |
| `jwt-dsub-ignored` | Ignored `dsub`, so a customized `sub` was trusted as the user's ID | 3 |
| `jwt-key-errors-look-like-token-errors` | Logged a broken key endpoint as an ordinary token rejection | 2 |
| `jwt-token-type-ignored` | Accepted tokens that say they are refresh or ID tokens | 4 |
| `jwt-lifetime-uncapped` | Put no limit on how long a token stays valid | 3 |
| `jwt-lifetime-capped-only-with-iat` | Checked the lifetime only when the token has `iat` | 1 |
| `jwt-lifetime-counted-from-now` | Counted the lifetime from now, so a long-lived token close to expiry passed | 1 |
| `jwt-empty-token-type-allowed` | Treated a null or empty `token_type` as no claim at all | 2 |
| `app-urls-not-standard-form` | Accepted configuration URLs that aren't in standard form | 9 |
| `app-key-url-on-any-host` | Accepted a key URL on any host | 1 |
| `app-get-allowed` | Let GET through again, with its never-ending stream | 4 |
| `app-challenge-without-scope` | 401 and 403 responses no longer name the required scope | 2 |
| `app-listen-enabled` | Left subscriptions on (the SDK default) | 1 |
| `app-stateful` | Ran with per-connection sessions, which share a global cap | 1 |
| `app-default-keep-alive` | Closed idle connections after uvicorn's default 5 seconds, sooner than Render's edge reuses them | 1 |
| `app-no-connection-limit` | Put no limit on simultaneous connections | 1 |

Result: **all 39 caught**, step 1's ten included (`shared-deck` and `key-by-client-id` now fail 33 tests each, because the step 2 end-to-end tests catch them too). As in section 2, a variant caught by only one or two tests depends on those tests, so those tests must not be removed.

## 6. Code reviews

### 2026-10-09: the verifier and the deployable app

A review by AI agents from four angles, with each finding re-checked by a second agent whose job was to disprove it:

- **Medium** (raised as High, lowered on re-check): without per-connection sessions, a GET on the 2025-era transport opened an event stream that never ended, so one free account could use up the server's memory. Fixed: the MCP path accepts POST only (anything else gets 405), subscriptions are off, and at most 400 connections are taken at a time. Covered by `app-get-allowed`, `app-listen-enabled` and `app-no-connection-limit`.
- **Also fixed:** configuration URLs must be in standard form, and every configuration error is listed at once; the key URL must be on the issuer's host; settings are compared with the provider's metadata at startup; keep-alive is 120 seconds, longer than the 75 seconds for which Render's edge reportedly reuses connections (to be confirmed after deployment); a token with a `dsub` claim is refused; a failing key endpoint logs one warning line.
- **Not reproduced:** "the same key id could come back with a different key". Each time Descope's keys were rotated in testing, the key id changed.
- **Deferred:**
  - while the key endpoint is failing, nothing is cached and there is no back-off (see section 8);
  - telling access tokens from other kinds of token. This waited for a real token and was added on 2026-10-12, with the review below.

### 2026-10-12: the token-type and lifetime checks, and this log

One AI agent reviewed the code change and another checked every claim in the README and this log against the code, the tests and the records. No High findings in the code. Fixed before committing:

- **Medium:** an `exp` written as a numeric string passes PyJWT, and the new lifetime check then raised an error instead of refusing the token (the SDK would have answered 500). It is now refused; covered by the `expiry-as-a-string` token.
- **Medium:** the tests read the one-day limit from the code, so raising the limit in the code wouldn't have failed them. The tests now spell out the documented day.
- **Medium:** no test told the declared lifetime (`exp` minus `iat`) from the time left. Added a token issued over a day ago that hasn't expired yet, and the `jwt-lifetime-counted-from-now` variant.
- **Low:** a null or empty `token_type` was treated as no claim. It is now refused, and `jwt-empty-token-type-allowed` covers it.
- **Documentation:** the README overstated what the `token_type` check covers, what the 30 seconds of clock tolerance apply to, and the manual isolation check (it was one-way), and it left out that SQLite on a host without a persistent disk loses every card on restart. This log called reviews by AI agents "independent", which reads like a third-party audit. All reworded.

## 7. Real sign-in with Descope and Claude Code (manual)

Setup: a Descope project on the free plan, with an MCP server registered for `http://localhost:8000/mcp`, scope `flashcards`, and both dynamic client registration and client ID metadata documents turned on. This repo's server ran locally against it.

| Date | What was done | Result |
|---|---|---|
| 2026-10-09 | Read Descope's published metadata | The issuer matches exactly. Client ID metadata documents and public clients are supported, so Claude Code uses a metadata document. Scopes `flashcards` and `offline_access`; PKCE with S256 |
| 2026-10-09 | Fetched the key set with Python's default User-Agent | 403. The verifier's own fetch works |
| 2026-10-09 | Signed in from Claude Code (`claude mcp add --transport http`): email one-time code, then the consent screen | The token was verified; `add_card` and `list_cards` worked |
| 2026-10-10 | Cleared the stored sign-in and signed in again with the same account | The same deck came back: identity follows the user, not the token |
| 2026-10-12 | Signed in with a second account (a different email) | The second account listed 0 cards while the first had 3 in the same database, and its first card was #1. The two tokens had different `sub` values, and the database had two owners |
| 2026-10-12 | Connected with the stored sign-in after adding the token-type and lifetime checks | Accepted (200) |

Shape of the real access tokens. Only claim names and non-personal values were logged, plus a short hash of `sub` to tell the two users apart; never the token, the email, or the user ID.

- Header: `alg` RS256, `typ` JWT, a `kid`.
- `iss`: `https://api.descope.com/v1/apps/agentic/<project ID>/<MCP server ID>`.
- `aud`: a list of three: Claude Code's client metadata URL, the project ID, and this server's URL last.
- `scope`: `flashcards`. `azp`: Claude Code's client metadata URL. No `client_id`.
- `token_type`: `access_token`. `amr`: `["oauth"]`. Valid for 600 seconds.
- Also present: `dci`, `email`, `iat`, `rexp`, `sub`. No `dsub`.

Found while preparing for and connecting the real project, and fixed before the first sign-in:
- Descope's key endpoint refuses Python's default User-Agent with 403, so the verifier sends its own. Found in research, then confirmed on the real project.
- Descope's metadata lists only RS256, but a project run by Descope itself publishes ES384 keys, so both are allowed. The MCP tokens above were RS256.
- Descope's documentation disagrees with itself about the issuer, so an issuer or audience mismatch logs what the token claimed.
- A mistyped MCP server ID produces no error: Descope serves the project-level metadata instead. The startup comparison with the provider's metadata now stops the server and says why. Tested against the real project.

# Step 3: Postgres storage and deployment (from 2026-10-12)

## 8. Postgres storage (automated)

The tests start a throwaway Postgres 18.6 server on `127.0.0.1` for the run (from `postgresql-binaries`, so no admin rights or Docker), with `psycopg` 3.3.6 and `psycopg-pool` 3.3.3, the versions the server pins. Every test that takes a store now runs twice, once on SQLite and once on Postgres, so sections 1 and 4 hold on both databases.

| What is proven | Test |
|---|---|
| Both databases return cards with the same fields, values and types | `test_store.py::test_cards_look_the_same_in_both_databases` |
| A refused add doesn't use up a card number | `test_store.py::test_a_refused_add_does_not_use_up_a_number` |
| Store calls run in a worker thread, not on the event loop | `test_store.py::test_store_calls_run_off_the_event_loop` |
| The largest card number a client may send is simply not found | `test_store.py::test_the_largest_card_number_is_simply_not_found` |
| Four simultaneous adds for one user can't go past the card limit. Deterministic: the user's row is held until all four are queued behind it, then released | `test_store_postgres.py::test_simultaneous_adds_cannot_go_past_the_card_limit` |
| A connection the server drops (as Neon does when it pauses) is replaced before the next request | `test_store_postgres.py::test_a_connection_dropped_by_the_server_is_replaced` |
| A failed statement rolls the whole add back, including its card number | `test_store_postgres.py::test_a_failed_statement_rolls_back_and_uses_no_number` |
| Startup creates the tables only when they are missing, and logs which database (name and host, never the URL) | `test_store_postgres.py::test_startup_creates_the_tables_once_and_says_which_database` |
| The database password stays out of the logs at DEBUG level, out of startup errors (including an unreachable database), and out of `repr(settings)` | `test_store_postgres.py::test_the_database_password_stays_out_of_logs_and_errors` |
| A bad database URL (no TLS to a remote host, not Postgres, no host, a bad port) is refused without repeating it; Render without a database URL, or both database settings at once, is refused | `test_app.py` |
| Text with a NUL character, which Postgres can't store, is refused the same way on both databases | `test_tools.py` |
| A database lost mid-service (the pool's connection dropped and no new one possible) ends in "unavailable", not the driver's own error | `test_store_postgres.py::test_a_database_lost_mid_service_is_reported_as_unavailable` |
| A full disk is reported as "out of space"; too many connections, in the same SQLSTATE class, still as "unavailable" | `test_store_postgres.py::test_running_out_of_space_is_not_reported_as_a_temporary_outage` |
| The tools turn those into "temporarily unavailable, try again in a minute" and "out of space", not a generic error | `test_tools.py::test_a_database_outage_gets_a_message_the_user_can_act_on`, `test_tools.py::test_a_full_database_is_not_reported_as_try_again_later` |
| The pool is set up for Neon: no server-side prepared statements, a connect timeout, TCP keepalives, room for four connections | `test_store_postgres.py::test_the_pool_is_set_up_for_neon` |
| Requests from origins listed in `FLASHCARDS_ALLOWED_ORIGINS` are served; other origins get 403 | `test_app.py::test_signed_requests_from_listed_origins_are_served` |
| uvicorn's own `Config` runs one process even with `WEB_CONCURRENCY=2` in the environment | `test_app.py::test_one_process_whatever_web_concurrency_says` |
| A password with unencoded `@`, `/` or `#` (which libpq would partly read as the host or database name, both logged) is refused; a percent-encoded one is fine; `hostaddr` pointing elsewhere doesn't count as local | `test_app.py` |
| `FLASHCARDS_ALLOWED_ORIGINS` entries that could never match (a default port, a bad port, a path, a wildcard host) are refused at startup; `http://localhost:*` is kept | `test_app.py` |

Result: **330 passed**, none skipped (with `FLASHCARDS_REQUIRE_PG=1`).

## 9. Mutation check, step 3 (2026-10-12)

The same runner, with the variants added in step 3. With a local Postgres available, the runner also requires the Postgres tests to run (a skip counts as a failure); the `pg-` variants break the Postgres store, and without a local Postgres they are reported as not run and the check fails. All 58 variants, steps 1 and 2 included, were rerun on this date.

| Broken variant | Mistake it simulates | Failing tests |
|---|---|---|
| `app-workers-from-environment` | Let uvicorn take its number of processes from `WEB_CONCURRENCY`, which Render sets; with more than one, uvicorn refuses to start an app passed as an object | 2 |
| `app-sqlite-allowed-on-render` | Let the server start on Render with a SQLite file that every restart wipes | 1 |
| `app-database-url-echoed` | Put the database URL, password included, into the configuration error | 11 |
| `app-database-url-unchecked` | Checked only the database URL's scheme: no host, port or TLS checks | 7 |
| `app-database-url-in-repr` | Showed the database URL in `repr(settings)` | 2 |
| `app-allowed-origins-ignored` | Ignored `FLASHCARDS_ALLOWED_ORIGINS`, so requests from a listed origin still got 403 | 11 |
| `app-origins-not-standardized` | Accepted allowed origins that could never match a browser's `Origin` header | 8 |
| `store-on-event-loop` | Ran store calls on the event loop, so one slow database call froze every other request | 3 |
| `text-nul-allowed` | Let text with a NUL character through, which Postgres can't store | 8 |
| `outage-unexplained` | Let a database outage reach the user as the SDK's generic error | 2 |
| `pg-number-from-max` | Numbered cards from the largest number in use, so a deleted card's number could be given out again | 2 |
| `pg-limit-checked-before-lock` | Checked the card limits before locking the user's row, so simultaneous adds could all get past them | 1 |
| `pg-number-in-own-transaction` | Took the card number in a transaction of its own, so a refused add still used it up | 2 |
| `pg-review-nulls-last` | Ordered by review time alone; Postgres puts never-reviewed cards last | 1 |
| `pg-unscoped-grade` | Step 1's `unscoped-grade` in the Postgres store: one query forgot its owner filter | 9 |
| `pg-no-connection-check` | Handed out pooled connections unchecked, so one the server had dropped failed the next request | 1 |
| `pg-request-errors-unmapped` | Passed the driver's own error on during requests instead of "unavailable" (startup still mapped it) | 1 |
| `pg-prepared-statements` | Left server-side prepared statements on, which work through Neon's pooler only with matching versions and settings | 1 |
| `pg-full-as-unavailable` | Reported a full database as a passing outage ("try again in a minute") | 1 |

Result: **all 58 caught**, none hung, invalid or left unrun. The 39 from steps 1 and 2 are still caught; `shared-deck` and `key-by-client-id` now fail 66 tests each, twice step 2's 33, because every store test runs on both databases. Step 1's storage variants (`unscoped-grade`, `review-ignores-time`, `unpaginated-list`) break only the SQLite store; the same tests run on Postgres, and `pg-unscoped-grade` shows they catch the missing owner filter there too. Most `pg-` variants are caught by a single test, and `pg-prepared-statements` only by a configuration check, so, as in section 2, those tests must not be removed.

## 10. Code review (2026-10-12)

Three AI review agents looked at the change (Postgres correctness, security and configuration with the documentation, test quality), and a second agent re-checked each finding. Fixed before committing:

- **High:** a variant that ran store calls on the event loop deadlocked the concurrency test (the row lock could never be released), and the mutation runner had no timeout, so the whole check would hang. Fixed: adds wait at most 10 seconds for a row lock (`SET LOCAL lock_timeout`), the test releases the row in a `finally`, and the runner reports a hung run as invalid after 10 minutes.
- **Medium:** the "temporarily unavailable" claim was only tested with a fake store; the real store's request path was not. Added the mid-service test and the `pg-request-errors-unmapped` variant.
- **Medium:** the concurrency test hung instead of failing when an add failed early. Fixed with the `finally` above.
- **Low:** a password with an unencoded `@` or `/` put part of itself into the logged host or database name; `hostaddr` could skip the TLS requirement; origins that could never match were accepted; a full disk was reported as a passing outage; no TCP keepalives or lock timeout; the connection pool logged three INFO lines per database call; the README promised cold-start behavior nobody had tested yet. All fixed or reworded.
- **Not reproduced:** a race between `pg_terminate_backend` and the next request. Postgres processes the termination before it reads the next query.

## 11. Known limitations and pending

- The rate limit is kept in memory, which is fine for a single server instance. A multi-instance deployment would need a shared store.
- The app runs without per-connection sessions; sections 1 and 4 test both protocol generations that way.
- While the provider's key endpoint is failing, every request retries the fetch: PyJWT keeps no stale keys and has no back-off.
- `token_type` is checked only when a token carries it. A provider that issued refresh tokens as JWTs without it would rely on the audience and one-day lifetime checks instead. Descope's access tokens carry it; whether its refresh and ID tokens for this server do hasn't been checked.
- The two-account check in section 7 was one-way by hand (the second account saw none of the first account's cards); the other direction is covered by the automated tests only.
- The Postgres tests use a local server with a direct connection. Neon's pooled connections (PgBouncer in transaction mode) are only exercised once deployed; the server avoids what that mode doesn't support (session settings, session-level locks) and turns off server-side prepared statements, which would depend on the pooler's version and settings.
- Only the packages the server imports directly are pinned; the packages they depend on are installed at whatever version is current when Render builds.
- The local test database uses the C locale, so the `COLLATE "C"` on the time columns (which keeps the review order independent of the database's locale) is never exercised against another locale.
- The local server trusts every connection, so the password tests never send a password; a rejected password was not tried. The keepalive timing can't be tested locally either.
- **Pending:**
  - deployment to Render with a Neon database, and sign-in from Claude Code and claude.ai against the deployed server;
  - what a request meets while a sleeping Render instance wakes (wait, an error, or a loading page);
  - retrying the key endpoint with back-off and keeping the last good keys.
