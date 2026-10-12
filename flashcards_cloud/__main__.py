"""Run the server:  python -m flashcards_cloud

Settings come from environment variables; see flashcards_cloud/app.py for the list.
"""

from __future__ import annotations

import logging
import os

import uvicorn

from .app import build_app, check_provider, load_settings, server_options


def main() -> None:
    settings = load_settings(os.environ)
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Without sessions the SDK logs "Terminating session: None" after every request.
    logging.getLogger("mcp.server.streamable_http").setLevel(logging.WARNING)
    check_provider(settings)
    uvicorn.run(build_app(settings), **server_options(settings))


if __name__ == "__main__":
    main()
