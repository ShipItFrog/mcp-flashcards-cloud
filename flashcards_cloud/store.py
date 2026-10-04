"""Card storage.

Every method takes an ``owner`` key and every SQL statement filters on it. There is
no way to read, change or delete a card without naming its owner, so one user can
never reach another user's cards through this module.

Card numbers are per owner (each user's first card is #1) and are never reused
after a delete, so a number someone remembers can't silently point at a new card.

Topics are matched case-insensitively: each card stores the topic as typed, plus a
normalized ``topic_key`` used for filtering (see ``topic_key``).
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import anyio.to_thread

MAX_CARDS_PER_OWNER = 1000
# Total characters (question + answer + topic) one owner may store. Bounds the
# database size per user on a free-tier database.
MAX_CHARS_PER_OWNER = 200_000


class CardLimitError(Exception):
    """The owner is at the card-count or total-size limit."""


def topic_key(topic: str) -> str:
    """Normalized form used to match topics: trimmed and case-folded."""
    return topic.strip().casefold()


class CardStore(Protocol):
    async def add(self, owner: str, question: str, answer: str, topic: str) -> dict[str, Any]: ...

    async def list(self, owner: str, topic: str = "", limit: int = 50, after_id: int = 0) -> list[dict[str, Any]]: ...

    async def count(self, owner: str, topic: str = "") -> int: ...

    async def least_recently_reviewed(self, owner: str, topic: str = "") -> dict[str, Any] | None: ...

    async def record_review(self, owner: str, card_no: int, correct: bool) -> dict[str, Any] | None: ...

    async def delete(self, owner: str, card_no: int) -> bool: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS owners (
    owner   TEXT PRIMARY KEY,
    next_no INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cards (
    owner         TEXT    NOT NULL,
    card_no       INTEGER NOT NULL,
    question      TEXT    NOT NULL,
    answer        TEXT    NOT NULL,
    topic         TEXT    NOT NULL,
    topic_key     TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    last_reviewed TEXT,
    review_count  INTEGER NOT NULL DEFAULT 0,
    correct_count INTEGER NOT NULL DEFAULT 0,
    wrong_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (owner, card_no)
);
CREATE INDEX IF NOT EXISTS cards_owner_topic ON cards (owner, topic_key);
"""

# The owner column is never selected: it is an internal key, not card data.
_CARD_COLUMNS = "card_no, question, answer, topic, created_at, last_reviewed, review_count, correct_count, wrong_count"


def _row_to_card(row: sqlite3.Row) -> dict[str, Any]:
    card = dict(row)
    card["id"] = card.pop("card_no")
    return card


def _topic_clause(topic: str) -> tuple[str, list[Any]]:
    key = topic_key(topic)
    return (" AND topic_key = ?", [key]) if key else ("", [])


class SqliteCardStore:
    """SQLite-backed store for local development and tests.

    Each call runs in a worker thread (so the event loop never waits on the disk)
    and holds a lock for its whole read-modify-write. There is no ``await`` inside
    the lock, so it can't deadlock the event loop.
    """

    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # --- async API (what the server calls) ---------------------------------

    async def add(self, owner: str, question: str, answer: str, topic: str) -> dict[str, Any]:
        return await anyio.to_thread.run_sync(self._add, owner, question, answer, topic)

    async def list(self, owner: str, topic: str = "", limit: int = 50, after_id: int = 0) -> list[dict[str, Any]]:
        return await anyio.to_thread.run_sync(self._list, owner, topic, limit, after_id)

    async def count(self, owner: str, topic: str = "") -> int:
        return await anyio.to_thread.run_sync(self._count, owner, topic)

    async def least_recently_reviewed(self, owner: str, topic: str = "") -> dict[str, Any] | None:
        return await anyio.to_thread.run_sync(self._least_recently_reviewed, owner, topic)

    async def record_review(self, owner: str, card_no: int, correct: bool) -> dict[str, Any] | None:
        return await anyio.to_thread.run_sync(self._record_review, owner, card_no, correct)

    async def delete(self, owner: str, card_no: int) -> bool:
        return await anyio.to_thread.run_sync(self._delete, owner, card_no)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # --- synchronous implementations (run in a worker thread) --------------

    def _add(self, owner: str, question: str, answer: str, topic: str) -> dict[str, Any]:
        with self._lock, self._conn:
            count, chars = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(question) + LENGTH(answer) + LENGTH(topic)), 0)"
                " FROM cards WHERE owner = ?",
                (owner,),
            ).fetchone()
            if count >= MAX_CARDS_PER_OWNER or chars + len(question) + len(answer) + len(topic) > MAX_CHARS_PER_OWNER:
                raise CardLimitError
            self._conn.execute("INSERT OR IGNORE INTO owners (owner, next_no) VALUES (?, 1)", (owner,))
            (card_no,) = self._conn.execute("SELECT next_no FROM owners WHERE owner = ?", (owner,)).fetchone()
            self._conn.execute("UPDATE owners SET next_no = next_no + 1 WHERE owner = ?", (owner,))
            self._conn.execute(
                "INSERT INTO cards (owner, card_no, question, answer, topic, topic_key, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (owner, card_no, question, answer, topic, topic_key(topic), _now()),
            )
            row = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ? AND card_no = ?", (owner, card_no)
            ).fetchone()
        return _row_to_card(row)

    def _list(self, owner: str, topic: str, limit: int, after_id: int) -> list[dict[str, Any]]:
        clause, params = _topic_clause(topic)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ? AND card_no > ?{clause} ORDER BY card_no LIMIT ?",
                [owner, after_id, *params, limit],
            ).fetchall()
        return [_row_to_card(r) for r in rows]

    def _count(self, owner: str, topic: str) -> int:
        clause, params = _topic_clause(topic)
        with self._lock:
            (n,) = self._conn.execute(f"SELECT COUNT(*) FROM cards WHERE owner = ?{clause}", [owner, *params]).fetchone()
        return n

    def _least_recently_reviewed(self, owner: str, topic: str) -> dict[str, Any] | None:
        clause, params = _topic_clause(topic)
        # Never-reviewed cards (NULL) first, then oldest review first.
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ?{clause}"
                " ORDER BY last_reviewed IS NOT NULL, last_reviewed, card_no LIMIT 1",
                [owner, *params],
            ).fetchone()
        return _row_to_card(row) if row else None

    def _record_review(self, owner: str, card_no: int, correct: bool) -> dict[str, Any] | None:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE cards SET last_reviewed = ?, review_count = review_count + 1,"
                " correct_count = correct_count + ?, wrong_count = wrong_count + ?"
                " WHERE owner = ? AND card_no = ?",
                (_now(), 1 if correct else 0, 0 if correct else 1, owner, card_no),
            )
            if cur.rowcount == 0:
                return None
            row = self._conn.execute(
                f"SELECT {_CARD_COLUMNS} FROM cards WHERE owner = ? AND card_no = ?", (owner, card_no)
            ).fetchone()
        return _row_to_card(row)

    def _delete(self, owner: str, card_no: int) -> bool:
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM cards WHERE owner = ? AND card_no = ?", (owner, card_no))
        return cur.rowcount > 0
