import os

import pytest

from flashcards_cloud.store import SqliteCardStore


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def store(tmp_path):
    s = SqliteCardStore(tmp_path / "cards.db")
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _apply_mutation(monkeypatch):
    """Only used by tests/run_mutations.py to prove the tests catch broken code."""
    name = os.environ.get("FLASHCARDS_MUTATION")
    if name:
        from mutations import MUTATIONS

        MUTATIONS[name](monkeypatch)
