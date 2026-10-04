"""Deliberately broken variants of the server, used only to prove the tests catch
real mistakes. Each one is applied with monkeypatch at test time (see conftest.py);
the source files are never modified.

Run all of them with:  python tests/run_mutations.py
Every mutation must make at least one test fail.
"""

from __future__ import annotations

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings

from flashcards_cloud import server
from flashcards_cloud import store as store_module

S = store_module


def _shared_deck(issuer: str) -> str:
    """Forgot the per-user key: everyone shares one deck."""
    return "everyone"


def _key_by_client_id(issuer: str) -> str:
    """Keys data by the OAuth client (the app) instead of the user."""
    return f"{issuer}|{get_access_token().client_id}"


def _no_subject_check(issuer: str) -> str:
    """Drops the 'token must have a subject' defence."""
    token = get_access_token()
    if (token.claims or {}).get("iss") != issuer:
        raise server.ToolError("Not signed in.")
    return f"{issuer}|{token.subject}"


def _no_issuer_check(issuer: str) -> str:
    """Trusts any issuer: the same `sub` from two identity providers becomes one person."""
    token = get_access_token()
    if token is None or not token.subject:
        raise server.ToolError("Not signed in.")
    return f"{issuer}|{token.subject}"


def _record_review_unscoped(self, owner, card_no, correct):
    """One query that forgot its owner filter."""
    with self._lock, self._conn:
        cur = self._conn.execute(
            "UPDATE cards SET last_reviewed = ?, review_count = review_count + 1,"
            " correct_count = correct_count + ?, wrong_count = wrong_count + ? WHERE card_no = ?",
            (S._now(), 1 if correct else 0, 0 if correct else 1, card_no),
        )
        if cur.rowcount == 0:
            return None
        row = self._conn.execute(f"SELECT {S._CARD_COLUMNS} FROM cards WHERE card_no = ?", (card_no,)).fetchone()
    return S._row_to_card(row)


def _least_recent_ignores_time(self, owner, topic):
    """Review order that only looks at 'reviewed or not', not when."""
    clause, params = S._topic_clause(topic)
    with self._lock:
        row = self._conn.execute(
            f"SELECT {S._CARD_COLUMNS} FROM cards WHERE owner = ?{clause}"
            " ORDER BY last_reviewed IS NOT NULL, card_no LIMIT 1",
            [owner, *params],
        ).fetchone()
    return S._row_to_card(row) if row else None


def _list_unpaginated(self, owner, topic, limit, after_id):
    """Listing that ignores the page size and cursor."""
    clause, params = S._topic_clause(topic)
    with self._lock:
        rows = self._conn.execute(
            f"SELECT {S._CARD_COLUMNS} FROM cards WHERE owner = ?{clause} ORDER BY card_no", [owner, *params]
        ).fetchall()
    return [S._row_to_card(r) for r in rows]


def _auth_without_audience_check(**kwargs):
    """Accepts tokens issued for any server."""
    kwargs["validate_token_resource"] = False
    return AuthSettings(**kwargs)


MUTATIONS = {
    "shared-deck": lambda mp: mp.setattr(server, "current_owner", _shared_deck),
    "key-by-client-id": lambda mp: mp.setattr(server, "current_owner", _key_by_client_id),
    "no-subject-check": lambda mp: mp.setattr(server, "current_owner", _no_subject_check),
    "no-issuer-check": lambda mp: mp.setattr(server, "current_owner", _no_issuer_check),
    "unscoped-grade": lambda mp: mp.setattr(S.SqliteCardStore, "_record_review", _record_review_unscoped),
    "no-audience-check": lambda mp: mp.setattr(server, "AuthSettings", _auth_without_audience_check),
    "review-ignores-time": lambda mp: mp.setattr(S.SqliteCardStore, "_least_recently_reviewed", _least_recent_ignores_time),
    "unpaginated-list": lambda mp: mp.setattr(S.SqliteCardStore, "_list", _list_unpaginated),
    "topic-not-normalized": lambda mp: mp.setattr(S, "topic_key", lambda topic: topic),
    "no-rate-limit": lambda mp: mp.setattr(server.RateLimiter, "check", lambda self, key: None),
}
