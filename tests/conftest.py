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


@pytest.fixture
def no_proxy(monkeypatch):
    """Tests that talk to a local HTTP server must not go through a proxy configured on
    the machine (urllib uses HTTP_PROXY or, on Windows, the system proxy)."""
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@pytest.fixture(autouse=True)
def _apply_mutation(monkeypatch):
    """Only used by tests/run_mutations.py to prove the tests catch broken code."""
    name = os.environ.get("FLASHCARDS_MUTATION")
    if name:
        from mutations import MUTATIONS

        MUTATIONS[name](monkeypatch)
