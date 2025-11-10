from __future__ import annotations

import asyncio

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .security import verify_request_security


async def sdk_weights(request: Request) -> JSONResponse:
    """Handle weights calculation request from validator."""
    from .server import lifecycle

    await verify_request_security(
        session_token=request.headers.get("X-Session-Token"),
        public_key=request.headers.get("X-Public-Key"),
        timestamp=request.headers.get("X-Timestamp"),
        nonce=request.headers.get("X-Nonce"),
        signature=request.headers.get("X-Signature"),
    )
    body = await request.json()
    jobs: list[dict] = body.get("jobs", [])
    if lifecycle.on_weights is None:
        return JSONResponse({"weights": {}, "meta": {"policy": "custom_required"}})
    result = lifecycle.on_weights(jobs)
    if asyncio.iscoroutine(result):
        result = await result
    if not isinstance(result, dict):
        raise HTTPException(status_code=500, detail="weights handler must return dict")
    return JSONResponse({"weights": result})


async def sdk_public(name: str, request: Request) -> JSONResponse:
    """Handle public API endpoint requests."""
    import os

    from .server import api

    # Public read-only endpoints that don't require signature verification
    PUBLIC_READONLY_ENDPOINTS = {"get_agent_status", "list_agents"}

    # Check for verified miner hotkey from platform-api (after signature verification)
    verified_hotkey = request.headers.get("X-Verified-Miner-Hotkey")

    if verified_hotkey:
        # Request came from platform-api with verified signature
        # Extract hotkey from header and set in token_info
        request.state.token_info = {
            "uid": "verified-uid",
            "miner_hotkey": verified_hotkey,
            "job_id": request.headers.get("X-Job-Id") or "",
            "challenge_id": os.getenv("CHALLENGE_ID", "challenge"),
            "job_type": "",
        }
    elif name in PUBLIC_READONLY_ENDPOINTS:
        # Public read-only endpoint: allow without signature verification
        # Set minimal token_info for compatibility
        request.state.token_info = {
            "uid": "public-readonly-uid",
            "miner_hotkey": request.headers.get("X-Miner-Hotkey") or "public",
            "job_id": request.headers.get("X-Job-Id") or "",
            "challenge_id": os.getenv("CHALLENGE_ID", "challenge"),
            "job_type": "",
        }
    else:
        # No verified header - check dev mode fallback (for local testing)
        dev_mode = os.getenv("SDK_DEV_MODE", "").lower() == "true"

        if dev_mode:
            # Dev mode: allow manual hotkey in header (for local testing)
            request.state.token_info = {
                "uid": "dev-uid",
                "miner_hotkey": request.headers.get("X-Miner-Hotkey") or "dev-miner",
                "job_id": request.headers.get("X-Job-Id") or "",
                "challenge_id": os.getenv("CHALLENGE_ID", "dev-challenge"),
                "job_type": "",
            }
        else:
            # Production mode: require verified header from platform-api
            raise HTTPException(
                status_code=401,
                detail="Missing X-Verified-Miner-Hotkey header. Requests must be proxied through platform-api with signature verification.",
            )

    handler = api.get(name)
    if handler is None:
        raise HTTPException(status_code=404, detail="public handler not found")
    result = handler(request)
    if asyncio.iscoroutine(result):
        result = await result

    # If handler already returned a JSONResponse, return it directly
    if isinstance(result, JSONResponse):
        return result

    # Otherwise, wrap in JSONResponse
    if isinstance(result, dict):
        return JSONResponse(result)
    else:
        return JSONResponse({"result": result})
