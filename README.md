# mcp-flashcards-cloud

A hosted, multi-user flashcards MCP server. Each person signs in with OAuth and sees only their own deck. Built on the official MCP Python SDK 2.x.

> **Status: work in progress.** Step 1 of 4 is done: the server, per-user isolation, abuse limits, and an automated test suite that proves one user can't read or change another user's cards. Still to come: real sign-in with an identity provider, deployment, and a full security write-up. See [TEST-LOG.md](TEST-LOG.md) for what has been verified.

## How isolation works

- **Identity comes only from the verified access token.** The server takes the token's subject (`sub`) after the SDK has checked the token, and keys all data by issuer plus subject. The token's own issuer must match the configured one, so the same `sub` from a different identity provider is a different person. Tool arguments, request metadata and headers are never used as identity, because a client controls all of them.
- **Isolation is enforced in code, not in prompts.** Every database query filters on the owner. There is no function that reads or changes a card without naming its owner.
- **Nothing leaks across users.** Card numbers are per user, so they reveal nothing about other decks. A card that belongs to someone else returns exactly the same "No card with id N" error as a card that doesn't exist.
- **Tokens for other servers are rejected.** The server only accepts tokens issued for its own URL (RFC 8707 audience check).

## Limits

This is meant to run on free-tier hosting with open sign-up, so one account must not be able to exhaust memory, storage, or the server's attention:

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
| `review(topic?)` | Draw the card you've gone longest without reviewing. Returns the question only. |
| `grade_card(card_id, correct)` | Record a right or wrong answer |
| `delete_card(card_id)` | Delete one of your cards |

## Run the tests

Requires Python 3.12+.

```
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
python tests/run_mutations.py   # proves the tests catch deliberately broken code
```

## License

MIT - see [LICENSE](LICENSE).
