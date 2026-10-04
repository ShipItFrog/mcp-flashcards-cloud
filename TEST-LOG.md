# Test log

Everything the README claims should be traceable to a row here. Rows marked **pending** have not been run yet.

## Environment

| Item | Value |
|---|---|
| MCP Python SDK | `mcp` 2.3.0 (`mcp-types` 2.3.0, `httpx2` 2.13.1) |
| Python | 3.14.5 |
| OS | Windows 11 |

## 1. Per-user isolation (automated, 2026-10-04)

The tests drive the real ASGI app over HTTP in-process, through the SDK's real auth middleware and a real MCP client. Only the token verifier is fake: it maps test tokens to users.

Every isolation test runs over four transports:
- the 2026-07-28 protocol;
- the 2025-era `initialize` handshake that claude.ai connectors use today;
- each of those against a stateless app as well.

The client asserts which protocol it actually negotiated. The SDK's auto mode silently falls back to the old handshake on errors, so without that check, a broken modern path would just test the old one twice.

| What is proven | Test |
|---|---|
| Another user lists and reviews nothing from your deck | `test_isolation.py::test_other_user_sees_none_of_your_cards` |
| Another user can't grade or delete your card by guessing its number, and your card is unchanged | `test_isolation.py::test_other_user_cannot_grade_or_delete_your_card_by_number` |
| Someone else's card returns exactly the same error as a missing card | `test_isolation.py::test_someone_elses_card_looks_exactly_like_a_missing_one` |
| The same person with a different token still sees their deck (identity is the user, not the token or the app) | `test_isolation.py::test_same_person_with_a_new_token_keeps_their_deck` |
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

## 2. Do the tests catch real mistakes? (mutation check, 2026-10-04)

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

Result: **all 10 caught.** Variants caught by only one or two tests depend on those tests, so they must not be removed.

## 3. Code review (2026-10-04)

An independent review (read-only, checked against the SDK source) found no way for one user to reach another's data. It did raise these issues, all fixed before this log was written:

- **High:** one account could make a single `list_cards` response tens of megabytes, and nothing limited call rates. Fixed with pagination, a total-size quota per user, shorter text limits, and a per-user rate limit.
- **Medium:** three places where tests could pass for the wrong reason. These were a review-order test that couldn't see an ordering bug, an unchecked protocol negotiation, and a mutation verdict that counted setup errors as caught. Fixed, and the first one is now covered by the `review-ignores-time` mutation.
- **Medium:** topic filters weren't normalized like stored topics, and the SDK turned the string `"null"` into "no filter". Fixed with case-insensitive matching and plain-string parameters.
- **Medium:** the storage key relied on the verifier accepting a single issuer. `identity.py` now checks the token's issuer itself.
- **Medium:** synchronous database calls ran on the event loop. They now run in a worker thread, and the concurrent-add test covers them.
- **Low (7):** card-id bounds, invalid Unicode, and several test and config gaps. All fixed.

## 4. Known limitations and pending

- The rate limit is kept in memory, which is fine for a single server instance. A multi-instance deployment would need a shared store.
- Sessions on the 2025-era transport share the SDK's global session cap. The deployment step will decide whether to run the app stateless; both modes are tested above.
- **Pending:**
  - real sign-in with an identity provider (JWT signature, issuer, audience and expiry checks), with its own tests;
  - deployment, and sign-in from Claude Code and claude.ai against the deployed server;
  - the production database.
