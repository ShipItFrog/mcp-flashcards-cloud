# mcp-flashcards-cloud

A multi-user flashcards MCP server, built to be hosted. Each person signs in with OAuth and sees only their own deck. Built on the official MCP Python SDK 2.x.

> **Status: work in progress.** Steps 1 and 2 of 4 are done:
> - the server, per-user isolation, abuse limits, and tests showing that one user can't read or change another user's cards;
> - real sign-in through an OAuth identity provider, tested locally with Descope and Claude Code, including a second real account that saw none of the first account's cards.
>
> Step 3 is under way: Postgres storage is written and tested on both databases; deployment to Render has not been tested yet. Still to come after that: a full security write-up. See [TEST-LOG.md](TEST-LOG.md) for what has been verified.

## How isolation works

- **Identity comes only from the verified access token.** The server takes the token's subject (`sub`) after the SDK has checked the token, and keys all data by issuer plus subject. The token's own issuer must also match the configured one, so a token from another identity provider is refused even if its `sub` matches a real user's. Tool arguments, request metadata and headers are never used as identity, because a client controls all of them.
- **Isolation is enforced in code, not in prompts.** Every database query filters on the owner. There is no function that reads or changes a card without naming its owner.
- **Replies give no hints about other users.** Card numbers are per user, so they reveal nothing about other decks. A card that belongs to someone else returns exactly the same "No card with id N" error as a card that doesn't exist.
- **Tokens for other servers are rejected.** The server only accepts tokens issued for its own URL (RFC 8707 audience check).

## How sign-in works

The server is an OAuth protected resource. It publishes metadata (RFC 9728) that tells clients such as Claude which identity provider to use, and a request without a valid token gets 401 with a pointer to that metadata. Claude signs the user in with the provider and sends the access token it gets back.

The server checks every token itself, with the provider's public signing keys, so it holds no secrets. A token is accepted only if:

- its signature is valid and made with one of the provider's keys. The allowed algorithms (RS256, ES384) are fixed by the server, never taken from the token;
- its issuer is exactly the configured one;
- its audience includes this server's URL, so a token the provider issued for another server is refused;
- it hasn't expired and isn't dated in the future (a provider clock up to 30 seconds ahead of this server's is tolerated);
- it names a user (`sub`) and has no `dsub` claim. Descope adds `dsub` when a token template has replaced `sub`, so `sub` may no longer be the user's ID;
- if it carries a `token_type` claim, that claim is `access_token`, so a refresh or ID token that says what it is can't stand in for an access token. A token without the claim is judged by the other checks only (Descope's access tokens carry it);
- it is valid for at most a day.

Tokens are never logged.

The MCP endpoint does only what it has to. It accepts POST only (anything else gets 405), runs without per-connection sessions, offers no subscriptions, and takes at most 400 connections at a time across all users (more get 503), so open streams can't exhaust the server's memory.

## Limits

This is meant to run on free-tier hosting with open sign-up, so one account must not be able to exhaust memory, storage, or CPU time:

| Limit | Value |
|---|---|
| Cards per user | 1,000 |
| Text stored per user (question + answer + topic) | 200,000 characters |
| Question / answer / topic length | 500 / 1,000 / 50 characters |
| `list_cards` page size | 50 by default, 100 at most |
| Tool calls per user | 120 per minute |

## Tools

| Tool | What it does |
|---|---|
| `add_card(question, answer, topic)` | Add a card to your deck |
| `list_cards(topic?, limit?, after_id?)` | List your cards a page at a time; pass `next_after_id` back as `after_id` for the next page. Topics match case-insensitively. |
| `review(topic?)` | Draw the card you've gone longest without reviewing. Returns the question, not the answer. |
| `grade_card(card_id, correct)` | Record a right or wrong answer |
| `delete_card(card_id)` | Delete one of your cards |

## Run it

Requires Python 3.12 or newer (tested on 3.14).

Register the server with your identity provider (Descope calls this an MCP server), then set these environment variables. Only `FLASHCARDS_DATABASE_URL` is a secret: it holds the database password, and the server never logs it or repeats it in an error.

| Variable | Meaning |
|---|---|
| `FLASHCARDS_ISSUER` | The provider's issuer, copied exactly from its metadata |
| `FLASHCARDS_JWKS_URL` | Where the provider publishes its public signing keys (`jwks_uri`); must be on the issuer's host |
| `FLASHCARDS_RESOURCE_URL` | This server's MCP URL, exactly as users enter it in Claude and as registered with the provider, e.g. `https://example.onrender.com/mcp` |
| `FLASHCARDS_SCOPES` | Optional: scopes every token must carry, e.g. `flashcards` |
| `FLASHCARDS_DATABASE_URL` | A Postgres connection URL, such as the one Neon gives you. Required on Render; a remote database must use `sslmode=require` or stricter. Characters such as `@ / ? #` in the password must be percent-encoded |
| `FLASHCARDS_DB` | Local use only: a SQLite file instead of Postgres (default `data/cards.db`). Set this or `FLASHCARDS_DATABASE_URL`, not both |
| `FLASHCARDS_ALLOWED_ORIGINS` | Optional: other web origins whose requests are accepted, e.g. `https://claude.ai`. Requests without an `Origin` header always are |
| `HOST`, `PORT` | Optional: where to listen (default `127.0.0.1` and `8000`; `0.0.0.0` on Render) |
| `LOG_LEVEL` | Optional: `DEBUG`, `INFO` (default), `WARNING` or `ERROR` |

```
pip install -r requirements.txt
python -m flashcards_cloud
```

Before it starts listening, the server reports every configuration problem at once, refuses plain http except on this machine, and compares the issuer and key URL with the provider's published metadata. A mistyped issuer, such as a wrong project or server ID inside it, then stops the server at startup instead of breaking the first sign-in. If the provider can't be reached, the server logs a warning and starts anyway. It also connects to the database and creates its tables if they don't exist yet.

### Storage

With `FLASHCARDS_DATABASE_URL` set, cards live in Postgres; otherwise in a local SQLite file. Both stores behave the same way and the tests run on both. On Postgres:

- Each store call borrows its own connection from a small pool and runs as one transaction, rolled back if anything fails.
- Card numbers come from an atomic update that also locks the user's row, so one user's simultaneous adds run one at a time and can't get past the card limits together. An add waits at most 10 seconds for that lock.
- The pool checks a connection before handing it out. Neon's free tier closes idle connections when it pauses after 5 minutes, and the next request gets a fresh one. TCP keepalives notice a connection that died without closing within about a minute.
- A database that can't be reached gets the user "temporarily unavailable, try again in a minute"; a full disk gets "out of space" instead.

Keep the `sslmode=require&channel_binding=require` that Neon puts in its URL. `sslmode=require` encrypts the connection without checking the server's certificate; channel binding ties the password exchange to that encrypted connection, so it can't be relayed by someone in between.

On a host without a persistent disk, such as Render, a SQLite file would be wiped on every restart, so the server refuses to start on Render without `FLASHCARDS_DATABASE_URL`.

### On Render

- Build command `pip install -r requirements.txt`, start command `python -m flashcards_cloud`. `.python-version` pins Python 3.14.
- The server runs as one process whatever `WEB_CONCURRENCY` says, and it listens on `0.0.0.0` and Render's `PORT` by itself.
- No health check path is needed. If you add one, don't point it at anything that queries the database, or the database never gets to pause.
- Render's free instances sleep after 15 minutes without traffic and take about a minute to wake. What a client meets during that minute hasn't been tested yet (see TEST-LOG). If a connection fails after a quiet spell, open `https://<your-service>.onrender.com/.well-known/oauth-protected-resource` in a browser, wait for the JSON, and connect again.

## Run the tests

```
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python tests/run_mutations.py   # checks that the tests catch 58 deliberately broken variants
```

`requirements-dev.txt` includes `postgresql-binaries`, a Postgres server the tests start on `127.0.0.1` for the run and stop afterwards (no admin rights needed). Every test that uses a store then runs once on SQLite and once on Postgres. Without a local Postgres those runs are skipped and listed as skipped; set `FLASHCARDS_REQUIRE_PG=1` to make them fail instead. `FLASHCARDS_TEST_PG_BIN` can point at another Postgres `bin` folder.

## License

MIT - see [LICENSE](LICENSE).
