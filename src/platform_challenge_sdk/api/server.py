from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, WebSocket

from .health import sdk_health
from .routes_admin import sdk_admin_db_credentials
from .routes_public import sdk_public, sdk_weights
from .security import validate_client_cert

_is_ready: bool = False
lifecycle: Any = None
api: Any = None


async def set_ready() -> None:
    """Mark challenge as ready and trigger on_ready lifecycle hook."""
    global _is_ready
    _is_ready = True
    if lifecycle and lifecycle.on_ready:
        res = lifecycle.on_ready()
        if asyncio.iscoroutine(res):
            await res


# Global app instance for route registration
_app_instance: FastAPI | None = None


def get_app_instance() -> FastAPI | None:
    """Get the global FastAPI app instance."""
    return _app_instance


async def init_app(lifecycle_registry: Any, api_registry: Any) -> FastAPI:
    """Initialize FastAPI application with SDK endpoints and lifecycle management.

    CHALLENGE_ADMIN determines available endpoints:
    - CHALLENGE_ADMIN=true: Public endpoints and admin handlers are registered
    - CHALLENGE_ADMIN=false/absent: Only WebSocket and health endpoints
    """
    global lifecycle, api, _app_instance
    lifecycle = lifecycle_registry
    api = api_registry

    app = FastAPI()
    _app_instance = app  # Store globally for route registration

    # Log dev mode status
    import os

    dev_mode = os.getenv("SDK_DEV_MODE", "").lower() == "true"
    if dev_mode:
        import logging

        logging.warning("🔧 DEV MODE ENABLED: Security checks bypassed, TDX attestation disabled")

    app.middleware("http")(validate_client_cert)

    @app.on_event("startup")
    async def on_startup():
        if lifecycle and lifecycle.on_startup:
            res = lifecycle.on_startup()
            if asyncio.iscoroutine(res):
                await res

    app.get("/sdk/health")(sdk_health)
    app.post("/sdk/weights")(sdk_weights)

    # Check CHALLENGE_ADMIN to determine if public endpoints should be registered
    import os

    challenge_admin = os.getenv("CHALLENGE_ADMIN", "").lower() == "true"

    if challenge_admin:
        # Admin mode: Register public endpoints and admin handlers
        # Support both GET and POST for public endpoints (GET for read-only endpoints like get_agent_status)
        app.get("/sdk/public/{name}")(sdk_public)
        app.post("/sdk/public/{name}")(sdk_public)
        app.post("/sdk/admin/db/credentials")(sdk_admin_db_credentials)

        # Register admin endpoints from api_registry
        # Admin endpoints can be registered via @challenge.api.admin("name")
        if api_registry and hasattr(api_registry, "admin_handlers"):
            admin_handlers = getattr(api_registry, "admin_handlers", {})
            for name, handler in admin_handlers.items():
                # Support both GET and POST (use GET for migrations)
                app.get(f"/sdk/admin/{name}")(handler)
                app.post(f"/sdk/admin/{name}")(handler)
    else:
        # Non-admin mode: No public endpoints or admin handlers
        # Only WebSocket and health endpoints are available
        pass

    # Minimal WS endpoint; actual handshake implemented in transport.ws
    @app.websocket("/sdk/ws")
    async def sdk_ws(websocket: WebSocket):
        await websocket.accept()
        # Defer to transport implementation via a simple adapter
        try:
            import os

            from ..transport.ws import serve_ws  # type: ignore

            # Check dev mode and mock attestation settings
            dev_mode = os.getenv("SDK_DEV_MODE", "").lower() == "true"
            tee_enforced = os.getenv("TEE_ENFORCED", "true").lower() != "false"
            tdx_simulation_mode = os.getenv("TDX_SIMULATION_MODE", "").lower() == "true"
            
            # Use mock quotes if in dev mode, TEE not enforced, or TDX simulation mode
            # In dev mode, always use mock quotes by default (don't try real SDK)
            # Priority: dev_mode > tdx_simulation_mode > not tee_enforced
            use_mock_quotes = dev_mode or tdx_simulation_mode or not tee_enforced

            async def quote_provider(report_data: bytes):
                import logging
                import secrets
                import json

                # Mock mode: generate fake quote (default for dev mode)
                if use_mock_quotes:
                    logging.info("🔧 MOCK MODE: Generating mock TDX quote (dev mode enabled, skipping dstack SDK)")
                    
                    # Generate a realistic mock quote with proper structure
                    # Embed report_data at common TDX offsets for nonce binding
                    fake_quote = bytearray(secrets.token_bytes(1024))
                    report_data_32 = report_data[:32]
                    
                    # Embed report_data at common offsets (568, 576, 584)
                    for offset in [568, 576, 584]:
                        if len(fake_quote) >= offset + 32:
                            fake_quote[offset:offset+32] = report_data_32
                    
                    # Generate realistic event log with compose-hash
                    compose_hash = os.getenv("COMPOSE_HASH", "dev-mode-mock")
                    challenge_id = os.getenv("CHALLENGE_ID", "term-challenge")
                    fake_event_log = json.dumps({
                        "dev_mode": True,
                        "environment_mode": "dev",
                        "compose-hash": compose_hash,
                        "app-id": f"challenge-{challenge_id}",
                        "instance-id": f"instance-{secrets.token_hex(8)}"
                    })
                    
                    # Generate RTMRs (48 bytes each, hex encoded)
                    fake_rtmrs = {
                        "rtmr0": secrets.token_bytes(48).hex(),
                        "rtmr1": secrets.token_bytes(48).hex(),
                        "rtmr2": secrets.token_bytes(48).hex(),
                        "rtmr3": secrets.token_bytes(48).hex(),
                    }
                    
                    logging.info(f"🔧 MOCK MODE: Mock quote generated ({len(fake_quote)} bytes) with report_data embedded")
                    return bytes(fake_quote), fake_event_log, fake_rtmrs

                # Production mode: use real TDX quote (only if not in dev mode)
                try:
                    from dstack_sdk import AsyncDstackClient  # type: ignore

                    logging.info(
                        f"quote_provider called with report_data (len={len(report_data)} bytes)"
                    )

                    client = AsyncDstackClient()
                    qr = await client.get_quote(report_data)

                    # Check compose-hash presence in event log
                    try:
                        evlog = qr.event_log or ""
                        if isinstance(evlog, str):
                            if '"compose-hash"' in evlog or '"upgraded-app-id"' in evlog:
                                logging.info("Event log contains compose-hash/upgraded-app-id")
                            else:
                                logging.warning(
                                    "Event log missing compose-hash (Platform-API may show UNKNOWN)"
                                )
                    except Exception:
                        # Event log parsing failed, non-critical
                        pass

                    # Log that report_data was received (but not the actual data)
                    if hasattr(qr, "report_data") and qr.report_data:
                        logging.info(
                            f"Report_data received from dstack SDK (len={len(qr.report_data) if isinstance(qr.report_data, str) else 'N/A'} chars)"
                        )

                    # Quote should be bytes or hex string - ensure it's bytes
                    quote = qr.quote
                    quote_len = len(quote) if quote else 0
                    logging.info(f"Quote received: {quote_len} bytes")
                    if isinstance(quote, str):
                        import binascii

                        # Try to decode as hex if it looks like hex
                        if all(c in "0123456789abcdefABCDEF" for c in quote.replace(" ", "")):
                            quote = binascii.unhexlify(quote.replace(" ", ""))
                        else:
                            quote = quote.encode("utf-8")

                    # Log quote for debugging
                    if quote:
                        import binascii

                        quote_hex = binascii.hexlify(quote).decode("ascii")
                        logging.info(
                            f"Quote received from dstack SDK: {len(quote)} bytes, hex (first 128 chars): {quote_hex[:128]}"
                        )

                        # (Debug) Extract a sample report_data slice; validator performs robust offset matching
                        if len(quote) >= 608:
                            report_data_in_quote_bytes = quote[576:608]
                            report_data_in_quote_hex = binascii.hexlify(
                                report_data_in_quote_bytes
                            ).decode("ascii")
                            logging.info(
                                f"Report_data sample from quote (offset 576): {report_data_in_quote_hex}"
                            )
                    else:
                        logging.warning("Quote is empty from dstack SDK")

                    # Verify quote is not empty
                    if not quote or len(quote) < 100:
                        logging.warning(
                            f"Quote is too short or empty: {len(quote) if quote else 0} bytes"
                        )
                        return b"", None, None

                    rtmrs = {}
                    try:
                        arr = qr.replay_rtmrs()  # replay_rtmrs is synchronous, not async
                        if isinstance(arr, (list, tuple)):
                            rtmrs = {
                                "rtmr0": arr[0] if len(arr) > 0 else None,
                                "rtmr1": arr[1] if len(arr) > 1 else None,
                                "rtmr2": arr[2] if len(arr) > 2 else None,
                                "rtmr3": arr[3] if len(arr) > 3 else None,
                            }
                    except Exception as e:
                        logging.debug(f"Could not get RTMRs: {e}")

                    logging.info(
                        f"Quote ready: {len(quote)} bytes, event_log present: {bool(qr.event_log)}"
                    )
                    return quote, qr.event_log, rtmrs
                except Exception as e:
                    import logging

                    logging.error(f"Failed to get quote from dstack SDK: {e}", exc_info=True)
                    # In dev/mock mode, generate fallback mock quote instead of returning empty
                    if use_mock_quotes:
                        logging.warning("🔧 MOCK MODE: dstack SDK failed, generating fallback mock quote")
                        # Generate a realistic mock quote with proper structure
                        fake_quote = bytearray(secrets.token_bytes(1024))
                        report_data_32 = report_data[:32]
                        
                        # Embed report_data at common TDX offsets for nonce binding
                        for offset in [568, 576, 584]:
                            if len(fake_quote) >= offset + 32:
                                fake_quote[offset:offset+32] = report_data_32
                        
                        # Generate realistic event log with compose-hash
                        compose_hash = os.getenv("COMPOSE_HASH", "dev-mode-fallback")
                        challenge_id = os.getenv("CHALLENGE_ID", "term-challenge")
                        fake_event_log = json.dumps({
                            "dev_mode": True,
                            "environment_mode": "dev",
                            "compose-hash": compose_hash,
                            "app-id": f"challenge-{challenge_id}",
                            "instance-id": f"instance-{secrets.token_hex(8)}"
                        })
                        
                        # Generate RTMRs (48 bytes each, hex encoded)
                        fake_rtmrs = {
                            "rtmr0": secrets.token_bytes(48).hex(),
                            "rtmr1": secrets.token_bytes(48).hex(),
                            "rtmr2": secrets.token_bytes(48).hex(),
                            "rtmr3": secrets.token_bytes(48).hex(),
                        }
                        
                        logging.info(f"🔧 MOCK MODE: Fallback mock quote generated ({len(fake_quote)} bytes) with report_data embedded")
                        return bytes(fake_quote), fake_event_log, fake_rtmrs
                    else:
                        # Production mode: no quote available
                        return b"", None, None

            await serve_ws(websocket, "/sdk/ws", quote_provider)
        except Exception as e:
            # Log the error but don't try to close if already closed
            import logging

            logging.error(f"WebSocket error: {e}", exc_info=True)
        finally:
            # Only close if still connected
            try:
                await websocket.close()
            except Exception:
                # WebSocket already closed or close failed, safe to ignore
                pass

    return app


sdk_app = FastAPI()
