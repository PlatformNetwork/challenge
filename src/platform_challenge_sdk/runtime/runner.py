from __future__ import annotations

import asyncio
import os

from ..challenge import Context


def _register_lifecycle_defaults() -> None:
    pass


async def _run_async_server() -> None:
    """Async runtime logic for WS server mode."""
    _register_lifecycle_defaults()
    # WS server mode: just start the FastAPI server
    # Validator will connect via WebSocket and initiate attestation
    from ..api.server import init_app, set_ready
    from ..challenge.decorators import challenge

    # LocalORMAdapter removed - using ServerORMAdapter with WebSocket connection
    # even in dev mode. This allows testing the production architecture with
    # mocked TDX attestation (TEE_ENFORCED=false, DEV_MODE=true).
    dev_mode = os.getenv("SDK_DEV_MODE", "").lower() == "true"

    app = await init_app(challenge, challenge.api)
    await set_ready()

    import uvicorn

    # Allow custom port
    port = int(os.getenv("SDK_PORT", "10000"))
    host = os.getenv("SDK_HOST", "0.0.0.0")  # noqa: S104

    import logging
    logger = logging.getLogger(__name__)
    if dev_mode:
        logger.info(f"🔧 DEV MODE: Starting server on {host}:{port} (using ServerORMAdapter via WebSocket)")
    else:
        logger.info(f"Starting server on {host}:{port}")

    config = uvicorn.Config(app, host=host, port=port)
    server = uvicorn.Server(config)
    await server.serve()


async def _run_async(ctx: Context) -> None:
    """Async runtime logic."""
    _register_lifecycle_defaults()
    # mTLS server removed - encryption now handled via X25519/ChaCha20-Poly1305


def run() -> None:
    """Main entry point for challenge runtime.

    The challenge always runs as a WebSocket server, regardless of CHALLENGE_ADMIN.
    CHALLENGE_ADMIN determines capabilities:
    - CHALLENGE_ADMIN=true: Migrations, ORM write, public endpoints (for platform-api)
    - CHALLENGE_ADMIN=false/absent: ORM read-only bridge, no migrations, no public endpoints (for platform-validator)
    """
    # Always run as WebSocket server (both platform-api and platform-validator connect to challenge)
    asyncio.run(_run_async_server())
