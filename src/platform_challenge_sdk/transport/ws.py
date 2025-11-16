from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
from typing import Any

from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base

from ..client.mtls import derive_aead_key  # reuse HKDF-compatible function
from .message_router import MessageRouter

try:
    import websockets
except ImportError:  # type: ignore
    websockets = None  # type: ignore


class AeadSession:
    def __init__(self, aead_key: bytes) -> None:
        self._key = aead_key

    def encrypt(self, obj: Any) -> dict[str, str]:
        from Crypto.Cipher import ChaCha20_Poly1305  # pycryptodome

        nonce = os.urandom(12)
        cipher = ChaCha20_Poly1305.new(key=self._key, nonce=nonce)
        plaintext = json.dumps(obj).encode("utf-8")
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return {
            "enc": "chacha20poly1305",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext + tag).decode("ascii"),
        }

    def decrypt(self, env: dict[str, Any]) -> Any:
        from Crypto.Cipher import ChaCha20_Poly1305

        if env.get("enc") != "chacha20poly1305":
            raise ValueError("unsupported enc")
        nonce = base64.b64decode(env["nonce"])  # 12B
        data = base64.b64decode(env["ciphertext"])  # ct||tag
        if len(nonce) != 12 or len(data) < 16:
            raise ValueError("invalid envelope")
        ct, tag = data[:-16], data[-16:]
        cipher = ChaCha20_Poly1305.new(key=self._key, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return json.loads(pt.decode("utf-8"))




async def verify_validator_quote(
    val_quote_b64: str,
    val_event_log: str | None,
    val_rtmrs: dict | None,
    nonce: bytes,
    dev_mode: bool,
    challenge_env_mode: str,
) -> dict[str, Any]:
    """Verify validator TDX quote for mutual attestation.

    Returns:
        dict with 'valid' (bool) and optional 'error' (str)
    """
    import logging

    try:
        # Decode quote
        val_quote_bytes = base64.b64decode(val_quote_b64)

        # Structural validation: quote must be at least 1024 bytes
        if len(val_quote_bytes) < 1024:
            return {
                "valid": False,
                "error": f"Validator quote too short: {len(val_quote_bytes)} bytes (minimum 1024)",
            }

        # Verify nonce binding: report_data must match SHA256(nonce)
        expected_report_data = hashlib.sha256(nonce).digest()[:32]

        # Check report_data at common TDX quote offsets
        candidate_offsets = [568, 576, 584]
        matched = False
        for offset in candidate_offsets:
            if len(val_quote_bytes) >= offset + 32:
                rd = val_quote_bytes[offset : offset + 32]
                if rd == expected_report_data:
                    matched = True
                    break

        if not matched:
            # In dev mode, be more lenient with mock quotes - they may not have proper nonce binding
            if dev_mode:
                logging.warning(
                    "DEV MODE: Nonce binding check failed for mock quote (accepting anyway)"
                )
                # Continue with validation but log the warning
            else:
                return {
                    "valid": False,
                    "error": "Validator quote report_data does not match nonce (nonce binding failed)",
                }

        # Verify environment mode isolation (dev/prod)
        if val_event_log:
            try:
                event_log_dict = (
                    json.loads(val_event_log) if isinstance(val_event_log, str) else val_event_log
                )
                val_env_mode = None

                # Check for environment_mode in event_log
                if isinstance(event_log_dict, dict):
                    val_env_mode = event_log_dict.get("environment_mode")
                    if not val_env_mode:
                        # Try to extract from dev_mode flag
                        if event_log_dict.get("dev_mode"):
                            val_env_mode = "dev"

                # Verify environment match (dev cannot connect to prod and vice versa)
                if val_env_mode and val_env_mode != challenge_env_mode:
                    return {
                        "valid": False,
                        "error": f"Environment mismatch: validator is '{val_env_mode}' but challenge is '{challenge_env_mode}'. Dev and prod environments cannot communicate.",
                    }
            except Exception as e:
                logging.warning(f"Failed to parse validator event_log for environment check: {e}")

        # In production, attempt cryptographic verification if dcap-qvl is available
        if not dev_mode:
            try:
                # Try to use dcap-qvl for cryptographic verification
                # Note: This requires dcap-qvl to be available in Python environment
                # For now, we do structural validation and environment check
                # Full cryptographic verification would require Python bindings for dcap-qvl
                logging.info("Validator quote structure and nonce binding verified")
            except Exception as e:
                logging.warning(f"Could not perform full cryptographic verification: {e}")
                # Structural validation passed, continue
        else:
            logging.info(
                "DEV MODE: Validator quote structure validated (cryptographic verification skipped)"
            )

        return {"valid": True}

    except Exception as e:
        return {
            "valid": False,
            "error": f"Validator quote verification error: {e}",
        }


async def serve_ws(websocket, path: str, quote_provider) -> None:
    from starlette.websockets import WebSocketDisconnect

    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"WebSocket connection received on path: {path}")
        # 1) Await attestation_begin
        # FastAPI/Starlette WebSocket API uses receive_text() instead of recv()
        begin_raw = await websocket.receive_text()
        logger.info(f"Received first message: {begin_raw[:100]}...")
        begin = json.loads(begin_raw)
        if begin.get("type") != "attestation_begin":
            logger.warning(f"Expected attestation_begin, got: {begin.get('type')}")
            return
        logger.info("Received attestation_begin, starting attestation process")

        nonce_hex = begin["nonce"]
        val_x25519_pub_b64 = begin["val_x25519_pub"]

        # Extract validator quote for mutual attestation
        val_quote_b64 = begin.get("val_quote")
        val_event_log = begin.get("val_event_log")
        val_rtmrs = begin.get("val_rtmrs")

        nonce = bytes.fromhex(nonce_hex)
        report_data = hashlib.sha256(nonce).digest()[:32]

        # Log that nonce was received (but not the actual data)
        import logging

        logging.info(f"Nonce received: {len(nonce_hex)} chars (hex)")
        logging.info("Report_data calculated from nonce (32 bytes)")

        # 1) Verify validator quote (mutual attestation)
        import os

        dev_mode = os.getenv("SDK_DEV_MODE", "").lower() == "true"
        tee_enforced = os.getenv("TEE_ENFORCED", "true").lower() != "false"
        tdx_simulation_mode = os.getenv("TDX_SIMULATION_MODE", "").lower() == "true"
        env_mode = os.getenv("ENVIRONMENT_MODE", "dev" if dev_mode else "prod")
        
        # In dev mode with TEE_ENFORCED=false or TDX_SIMULATION_MODE=true, accept mock quotes
        use_mock_attestation = not tee_enforced or tdx_simulation_mode or dev_mode

        if val_quote_b64:
            # Validate validator quote structure and environment
            validation_result = await verify_validator_quote(
                val_quote_b64,
                val_event_log,
                val_rtmrs,
                nonce,
                dev_mode,
                env_mode,
            )

            if not validation_result["valid"]:
                error_msg = validation_result.get("error", "Validator quote verification failed")
                # In mock mode, accept quotes even if verification fails (they're mock quotes)
                if use_mock_attestation:
                    logging.warning(
                        f"DEV/MOCK MODE: Validator quote verification failed but accepting mock quote: {error_msg}"
                    )
                    logging.info("Accepting connection with mock attestation")
                else:
                    logging.error(f"Validator quote verification failed: {error_msg}")
                    await websocket.send_text(
                        json.dumps(
                            {
                                "type": "attestation_reject",
                                "reason": error_msg,
                            }
                        )
                    )
                    return
            else:
                logging.info("Validator quote verified (mutual attestation)")
        else:
            # In production, validator quote is required
            if not use_mock_attestation:
                logging.error(
                    "Security error: Validator quote required for mutual attestation in production"
                )
                await websocket.send_text(
                    json.dumps(
                        {
                            "type": "attestation_reject",
                            "reason": "Validator quote required for mutual attestation",
                        }
                    )
                )
                return
            else:
                logging.warning(
                    "DEV/MOCK MODE: Validator quote not provided (mutual attestation skipped)"
                )

        # 2) Generate challenge X25519 keypair and quote
        chal_sk = secrets.token_bytes(32)
        chal_pub = crypto_scalarmult_base(chal_sk)

        quote, event_log, rtmrs = await quote_provider(report_data)

        # Validate quote before sending - must not be empty (unless mock mode)
        quote_len = len(quote) if quote else 0
        if not quote or quote_len < 100:
            import logging

            if use_mock_attestation:
                # In mock mode, generate a fake quote if provider returned empty
                logging.warning("🔧 MOCK MODE: Quote provider returned empty, generating fallback mock quote")
                quote_bytes = bytearray(secrets.token_bytes(1024))
                # Embed report_data for nonce binding
                report_data_32 = report_data[:32]
                for offset in [568, 576, 584]:
                    if len(quote_bytes) >= offset + 32:
                        quote_bytes[offset:offset+32] = report_data_32
                quote = bytes(quote_bytes)
                if not event_log:
                    event_log = json.dumps({
                        "dev_mode": True,
                        "environment_mode": "dev",
                        "compose-hash": os.getenv("COMPOSE_HASH", "dev-mode-fallback")
                    })
                if not rtmrs:
                    rtmrs = {}
            else:
                logging.error(
                    f"Quote is empty or too short ({quote_len} bytes), closing WebSocket connection"
                )
                return

        # Include environment mode in event_log for isolation check
        if event_log and isinstance(event_log, str):
            try:
                import json as json_lib

                event_log_dict = (
                    json_lib.loads(event_log) if isinstance(event_log, str) else event_log
                )
                if isinstance(event_log_dict, dict):
                    event_log_dict["environment_mode"] = env_mode
                    event_log = json_lib.dumps(event_log_dict)
            except Exception:
                # If event_log parsing fails, add environment_mode as string
                if event_log:
                    event_log = json.dumps({"environment_mode": env_mode, "original": event_log})
                else:
                    event_log = json.dumps({"environment_mode": env_mode})

        # FastAPI/Starlette WebSocket API uses send_text() instead of send()
        await websocket.send_text(
            json.dumps(
                {
                    "type": "attestation_response",
                    "quote": (
                        base64.b64encode(quote).decode("ascii")
                        if isinstance(quote, bytes)
                        else quote
                    ),
                    "event_log": event_log,
                    "rtmrs": rtmrs,
                    "chal_x25519_pub": base64.b64encode(chal_pub).decode("ascii"),
                }
            )
        )

        # Check dev mode for logging purposes
        dev_mode = os.getenv("SDK_DEV_MODE", "").lower() == "true"
        tdx_simulation_mode = os.getenv("TDX_SIMULATION_MODE", "").lower() == "true"
        
        # Always use encryption
        import logging
        
        if dev_mode or tdx_simulation_mode:
            logging.info("DEV MODE: Using encrypted session with mock TDX attestation")
        else:
            logging.info("Production mode: Using encrypted session with real TDX attestation")
        
        # Wait for attestation_ok and derive keys
        ok_raw = await websocket.receive_text()
        ok = json.loads(ok_raw)
        if ok.get("type") != "attestation_ok":
            return

        hkdf_salt_b64 = ok.get("hkdf_salt") or ok.get(
            "hkdf_salt_b64", ""
        )  # Support both field names
        if not hkdf_salt_b64:
            return

        val_pub = base64.b64decode(val_x25519_pub_b64)
        shared = crypto_scalarmult(chal_sk, val_pub)
        aead_key = derive_aead_key(shared, hkdf_salt_b64)
        session = AeadSession(aead_key)

        # Create a queue for outgoing messages (contains JSON strings of encrypted envelopes)
        # This allows concurrent sends from background tasks
        outgoing_queue = asyncio.Queue()

        # Task to send messages from queue to WebSocket (serialized sending)
        async def send_queue_worker():
            """Worker task that serializes all WebSocket sends from the queue."""
            logging.info("Queue worker started - ready to send messages via WebSocket")
            message_count = 0
            while True:
                try:
                    # Wait for message to send (already encrypted JSON string)
                    msg = await outgoing_queue.get()
                    if msg is None:  # Sentinel to stop
                        logging.info(f"Queue worker stopping (sent {message_count} messages)")
                        break

                    message_count += 1
                    # Try to extract message type and ID for logging (if JSON parseable)
                    try:
                        msg_dict = json.loads(msg)
                        msg_type = msg_dict.get("type", "unknown")
                        msg_id = msg_dict.get("message_id") or msg_dict.get("query_id") or "unknown"
                        # For encrypted messages, we can't parse the inner structure easily
                        # So we'll log the outer structure if it's an encrypted envelope
                        if "enc" in msg_dict:
                            logging.debug(
                                f"Queue worker: Sending encrypted message #{message_count}"
                            )
                        else:
                            logging.info(
                                f"Queue worker: Sending message #{message_count} type={msg_type} id={msg_id}"
                            )
                    except Exception:
                        # If we can't parse for logging, just send it
                        logging.debug(
                            f"Queue worker: Sending message #{message_count} (non-JSON or encrypted)"
                        )

                    await websocket.send_text(msg)
                    outgoing_queue.task_done()
                    # (Logging removed for verbosity)
                except Exception as e:
                    logging.error(
                        f"Queue worker error sending message #{message_count}: {e}",
                        exc_info=True,
                    )
                    # Continue processing other messages even if one fails
                    outgoing_queue.task_done()

        # Start queue worker
        send_task = asyncio.create_task(send_queue_worker())

        # Create MessageRouter for centralized message handling with encryption
        router = MessageRouter(session=session, outgoing_queue=outgoing_queue)

        # Register handlers for different message types
        # These handlers receive decrypted messages

        async def handle_migrations_request(msg: dict) -> None:
            """Handle migrations_request and send response via router."""
            import os

            challenge_admin = os.getenv("CHALLENGE_ADMIN", "").lower() == "true"

            if not challenge_admin:
                # Non-admin mode: Return empty migrations response
                logging.info(
                    "migrations_request received but CHALLENGE_ADMIN=false, returning empty migrations"
                )
                await router.send_push_message(
                    {
                        "type": "migrations_response",
                        "message_id": msg.get("message_id"),  # Include original message_id
                        "payload": {"migrations": [], "db_version": 1},
                    }
                )
                return

            logging.info("Received migrations_request, processing...")

            # Get DB version from challenge registry
            from ..challenge.decorators import challenge

            db_version = challenge.db_version or 1  # Default to 1 if not set
            logging.info(f"DB version: {db_version}")

            migrations = []
            # Try multiple possible paths for migrations directory
            # In Docker, the challenge code is typically mounted at /app/term-challenge
            # The working directory is usually /app
            possible_paths = [
                "db/migrations/v1",  # Relative to current working directory
                "term-challenge/db/migrations/v1",  # If working dir is /app
                os.path.join(os.getcwd(), "db", "migrations", f"v{db_version}"),
                os.path.join(os.getcwd(), "term-challenge", "db", "migrations", f"v{db_version}"),
            ]
            
            # Also try to find db/migrations by walking up from current directory
            current_dir = os.getcwd()
            for _ in range(5):  # Walk up max 5 levels
                test_path = os.path.join(current_dir, "db", "migrations", f"v{db_version}")
                if os.path.exists(test_path):
                    possible_paths.insert(0, test_path)
                    break
                # Also try term-challenge subdirectory
                test_path_term = os.path.join(current_dir, "term-challenge", "db", "migrations", f"v{db_version}")
                if os.path.exists(test_path_term):
                    possible_paths.insert(0, test_path_term)
                    break
                parent = os.path.dirname(current_dir)
                if parent == current_dir:  # Reached root
                    break
                current_dir = parent
            
            migrations_dir = None
            for path in possible_paths:
                if os.path.exists(path) and os.path.isdir(path):
                    migrations_dir = path
                    logging.info(f"Found migrations directory: {migrations_dir}")
                    break
            
            if migrations_dir and os.path.exists(migrations_dir):
                for filename in sorted(os.listdir(migrations_dir)):
                    if filename.endswith(".sql"):
                        filepath = os.path.join(migrations_dir, filename)

                        # Extract version and name from filename
                        version = filename.split("_")[0]  # "001"
                        name = filename.replace(".sql", "")  # "001_create_users"

                        try:
                            with open(filepath) as f:
                                sql = f.read()
                                checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()

                            migrations.append(
                                {
                                    "version": version,
                                    "name": name,
                                    "sql": sql,
                                    "checksum": checksum,
                                }
                            )
                            logging.info(f"Loaded migration: {name} ({len(sql)} bytes SQL)")
                        except Exception as e:
                            logging.error(f"Failed to read migration {filename}: {e}")
                            continue
            else:
                if migrations_dir:
                    logging.warning(f"Migrations directory {migrations_dir} does not exist")
                else:
                    logging.warning("Could not find migrations directory in any of the expected locations")

            # Send migrations_response with db_version
            logging.info(
                f"Preparing migrations_response: {len(migrations)} migrations found, db_version={db_version}"
            )
            if migrations:
                logging.info(f"Migration versions: {[m.get('version') for m in migrations]}")
            else:
                logging.warning("No migrations found - sending empty migrations list")
            
            await router.send_push_message(
                {
                    "type": "migrations_response",
                    "message_id": msg.get("message_id"),  # Include original message_id
                    "payload": {"migrations": migrations, "db_version": db_version},
                }
            )
            logging.info(
                f"✅ Sent migrations_response: {len(migrations)} migrations, db_version={db_version}"
            )

        async def handle_db_version_request(msg: dict) -> None:
            """Handle db_version_request and send response via router."""
            from ..challenge.decorators import challenge

            db_version = challenge.db_version or 1  # Default to 1 if not set

            await router.send_push_message(
                {
                    "type": "db_version_response",
                    "message_id": msg.get("message_id"),  # Include original message_id
                    "payload": {"db_version": db_version},
                }
            )

        async def handle_orm_ready(msg: dict) -> None:
            """Handle orm_ready signal from platform-api."""
            logging.info("✅ Received orm_ready signal from platform-api - initializing ServerORMAdapter")

            # Platform-api sends schema name in orm_ready, but SDK does not store it
            # Platform-api will set the schema for each ORM query - SDK just sends queries without schema
            schema_name = msg.get("schema") or (
                msg.get("payload", {}).get("schema")
                if isinstance(msg.get("payload"), dict)
                else None
            )
            if schema_name:
                logging.info(f"Platform-api schema: {schema_name} (SDK will not store or use this)")
            else:
                logging.warning(
                    "WARNING: orm_ready signal missing schema name (non-fatal, platform-api will set schema per query)"
                )

            # Initialize server-side ORM adapter
            try:
                import os

                from ..challenge.decorators import challenge
                from ..orm.server_adapter import ServerORMAdapter

                challenge_id = os.getenv("CHALLENGE_ID", "")
                if challenge_id and (
                    not hasattr(challenge, "_server_orm_adapter")
                    or not challenge._server_orm_adapter
                ):
                    # Get permissions (use default if not set)
                    from ..orm.permissions import ORMPermissions

                    permissions = (
                        challenge.orm_permissions if challenge.orm_permissions else ORMPermissions()
                    )

                    # Create server-side ORM adapter WITHOUT schema - platform-api manages schemas
                    # Platform-api will set the schema for each query based on challenge configuration
                    challenge._server_orm_adapter = ServerORMAdapter(
                        router=router,  # Pass router instead of session and queue
                        permissions=permissions,
                        challenge_id=challenge_id,
                        # No schema_name parameter - platform-api controls schemas
                    )
                    logging.info(
                        f"Server-side ORM adapter initialized for challenge {challenge_id} (schema managed by platform-api)"
                    )
            except Exception as e:
                logging.error(f"Failed to initialize server-side ORM adapter: {e}", exc_info=True)

            # Send ORM permissions if defined
            try:
                import os

                from ..challenge.decorators import challenge

                # Get challenge_id from environment
                challenge_id = os.getenv("CHALLENGE_ID", "")

                if challenge.orm_permissions and challenge_id:
                    logging.info("Sending ORM permissions to platform-api...")

                    # Convert permissions to dict format expected by platform-api
                    permissions_dict = challenge.orm_permissions.to_dict()

                    # Send orm_permissions message (push, no response expected)
                    await router.send_push_message(
                        {
                            "type": "orm_permissions",
                            "challenge_id": challenge_id,
                            "permissions": permissions_dict,
                        }
                    )
                    logging.info(
                        f"ORM permissions sent for challenge {challenge_id} ({len(permissions_dict)} tables)"
                    )
                else:
                    if not challenge.orm_permissions:
                        logging.debug("No ORM permissions defined (using permissive mode)")
                    if not challenge_id:
                        logging.warning("CHALLENGE_ID not set, cannot send permissions")
            except Exception as e:
                logging.error(f"Failed to send ORM permissions: {e}", exc_info=True)

            # Call registered handler via challenge registry
            try:
                from ..challenge.decorators import challenge

                if challenge.orm_ready_handler:
                    logging.info("Calling registered on_orm_ready handler...")
                    handler = challenge.orm_ready_handler
                    if asyncio.iscoroutinefunction(handler):
                        # Schedule handler to run in background
                        asyncio.create_task(handler())
                    else:
                        # Run synchronously if not async
                        handler()
                    logging.info("✅ on_orm_ready handler scheduled - services should now be initialized")
                else:
                    logging.warning("⚠️  No on_orm_ready handler registered - services will not be initialized!")
            except Exception as e:
                logging.error(f"Failed to call on_orm_ready handler: {e}", exc_info=True)

        async def handle_orm_result(msg: dict) -> None:
            """Handle orm_result messages - responses from platform-api for server-side ORM queries."""
            # Extract query_id or message_id for routing
            query_id = msg.get("query_id") or msg.get("message_id")

            if query_id:
                # (Logging removed for verbosity)
                # This is a response to a server-side ORM query
                # Forward to the ServerORMAdapter if it exists
                from ..challenge.decorators import challenge

                if hasattr(challenge, "_server_orm_adapter") and challenge._server_orm_adapter:
                    try:
                        # query_id might be a string, convert if needed
                        query_id_str = query_id if isinstance(query_id, str) else str(query_id)
                        # The router already matched the response to the request, but we can still
                        # forward to the adapter if it has specific handling
                        if hasattr(challenge._server_orm_adapter, "handle_orm_result"):
                            await challenge._server_orm_adapter.handle_orm_result(query_id_str, msg)
                    except Exception as e:
                        logging.error(f"Failed to handle ORM result: {e}", exc_info=True)
            else:
                logging.warning(
                    "Received orm_result without query_id/message_id, cannot route response"
                )

        async def handle_job_execute(msg: dict) -> None:
            """Handle job_execute message from platform-api/validator via WebSocket."""
            import asyncio
            import os

            from ..challenge.context import Context
            from ..challenge.decorators import challenge

            job_name = msg.get("job_name")  # Job name to execute
            payload = msg.get("payload", {})  # Job payload
            job_id = msg.get("job_id")  # Job ID for response

            # Select the appropriate handler
            handler = None
            if job_name and job_name in challenge.job_handlers:
                handler = challenge.job_handlers[job_name]
            elif challenge.job_handler:
                handler = challenge.job_handler  # Default handler
            else:
                await router.send_push_message(
                    {
                        "type": "job_result",
                        "job_id": job_id,
                        "error": (
                            f"No job handler found for '{job_name}'"
                            if job_name
                            else "No default job handler found"
                        ),
                    }
                )
                return

            # Create context from environment variables
            ctx = Context(
                validator_base_url=os.getenv("VALIDATOR_BASE_URL", "http://validator:8080"),
                session_token=os.getenv("SESSION_TOKEN", ""),
                job_id=job_id or os.getenv("JOB_ID", ""),
                challenge_id=os.getenv("CHALLENGE_ID", ""),
                validator_hotkey=os.getenv("VALIDATOR_HOTKEY", "validator"),
                client=None,  # Will be initialized if needed
                cvm=None,  # Will be initialized if needed
                values=None,  # Will be initialized if needed
                results=None,  # Will be initialized if needed
            )

            # Execute handler asynchronously
            async def execute_handler():
                try:
                    if asyncio.iscoroutinefunction(handler):
                        result = await handler(ctx, payload)
                    else:
                        result = handler(ctx, payload)

                    # Send the result
                    await router.send_push_message(
                        {
                            "type": "job_result",
                            "job_id": job_id,
                            "result": result,
                        }
                    )
                except Exception as e:
                    logging.error(f"Error executing job handler: {e}", exc_info=True)
                    await router.send_push_message(
                        {
                            "type": "job_result",
                            "job_id": job_id,
                            "error": str(e),
                        }
                    )

            # Execute in background (asynchronous)
            asyncio.create_task(execute_handler())

        async def handle_validator_status_update(msg: dict) -> None:
            """Handle validator_status_update message from platform-api.
            
            Updates the ValidatorPool with validator information from platform-api.
            This ensures the challenge knows which validators are available for job distribution.
            """
            import os
            import sys
            
            try:
                compose_hash = msg.get("compose_hash", "")
                validators = msg.get("validators", [])
                
                logging.info(
                    f"📥 Received validator_status_update: {len(validators)} validators for compose_hash={compose_hash}"
                )
                
                if not validators:
                    logging.warning("Received empty validator list from platform-api")
                    return
                
                # Try to get ValidatorPool from term-challenge if available
                # This is a soft dependency - if ValidatorPool is not available, we just log
                validator_pool = None
                try:
                    # Try importing from services.validator_pool (term-challenge specific)
                    from services.validator_pool import get_validator_pool
                    validator_pool = get_validator_pool()
                    logging.debug("Successfully imported get_validator_pool from services.validator_pool")
                except ImportError as e:
                    # ValidatorPool is specific to term-challenge, not available in base SDK
                    logging.debug(f"ValidatorPool not available (expected for base SDK): {e}")
                    return
                except Exception as e:
                    logging.warning(f"Failed to import ValidatorPool: {e}", exc_info=True)
                    return
                
                if not validator_pool:
                    logging.warning(
                        "ValidatorPool not initialized yet (will be available after on_orm_ready). "
                        "Will retry when pool is ready."
                    )
                    # Store validators temporarily? Or just wait for next update?
                    # For now, we'll just log and wait for the next periodic update
                    return
                
                # Update validator pool
                registered_count = 0
                for validator_data in validators:
                    if isinstance(validator_data, dict):
                        hotkey = validator_data.get("hotkey")
                        status = validator_data.get("status", "active")
                        
                        if hotkey:
                            is_active = status == "active"
                            validator_pool.register_validator(
                                hotkey=hotkey,
                                compose_hash=compose_hash,
                                is_active=is_active
                            )
                            registered_count += 1
                            logging.debug(f"Registered validator: {hotkey} (active={is_active})")
                
                active_count = len(validator_pool.get_active_validators(compose_hash))
                logging.info(
                    f"✅ Updated validator pool: {registered_count} validators registered, "
                    f"{active_count} active for compose_hash={compose_hash}"
                )
                    
            except Exception as e:
                logging.error(f"Error handling validator_status_update: {e}", exc_info=True)

        # Register all handlers
        router.register_handler("migrations_request", handle_migrations_request)
        router.register_handler("db_version_request", handle_db_version_request)
        router.register_handler("orm_ready", handle_orm_ready)
        router.register_handler("orm_result", handle_orm_result)
        router.register_handler("job_execute", handle_job_execute)
        router.register_handler("validator_status_update", handle_validator_status_update)

        # Assign router to challenge registry for global access
        try:
            from ..challenge.decorators import challenge

            challenge.message_router = router
            # Store send_task reference for health checks (optional - mainly for debugging)
            router._send_task = send_task  # type: ignore
            router._websocket_active = True  # type: ignore
            logging.info("MessageRouter initialized and assigned to challenge registry")
        except Exception as e:
            logging.error(
                f"Failed to assign MessageRouter to challenge registry: {e}", exc_info=True
            )

        # 4) Message loop: handle messages via router
        import logging

        # Always using encryption
        logging.info("Entering encrypted message loop (using ChaCha20-Poly1305)")

        while True:
            try:
                msg_raw = await websocket.receive_text()
                msg = json.loads(msg_raw)

                # The router will decrypt the ChaCha20-Poly1305 encrypted message
                await router.handle_incoming_message(msg)

                # Note: All message handling is now done by registered handlers in the router
                # The router automatically:
                # 1. Decrypts the message
                # 2. Matches responses to pending requests
                # 3. Routes to registered handlers based on message type

            except WebSocketDisconnect:
                # Client disconnected, exit gracefully
                logging.warning(
                    "WARNING: WebSocket disconnected by client - ORM queries will fail until reconnected"
                )
                # Mark router as inactive and cancel all pending requests
                try:
                    from ..challenge.decorators import challenge

                    if hasattr(challenge, "message_router") and challenge.message_router:
                        router = challenge.message_router
                        router._websocket_active = False  # type: ignore
                        # Cancel all pending requests to avoid timeouts
                        for message_id, future in router._pending_requests.items():
                            if not future.done():
                                future.cancel()
                                logging.debug(f"Cancelled pending request: {message_id}")
                        router._pending_requests.clear()
                except Exception as e:
                    # Failed to update router state, non-critical during disconnect
                    logging.debug(f"Failed to update router state during disconnect: {e}")
                # Signal queue worker to stop
                await outgoing_queue.put(None)
                break
            except json.JSONDecodeError as e:
                # Ignore malformed JSON
                logging.warning(f"Failed to parse JSON: {e}")
                continue
            except Exception as e:
                # Log errors in decryption/processing for debugging
                logging.error(f"Error processing message: {e}", exc_info=True)
                continue
    except WebSocketDisconnect:
        # Client disconnected during handshake
        pass
    except Exception as e:
        import logging

        logging.error(f"WebSocket serve_ws error: {e}", exc_info=True)
    finally:
        # Cleanup: stop queue worker if it was started
        if "send_task" in locals():
            try:
                if "outgoing_queue" in locals():
                    await outgoing_queue.put(None)  # Signal to stop
                    await asyncio.wait_for(send_task, timeout=1.0)  # Wait for task to finish
            except Exception:
                # Cleanup errors during shutdown are non-critical
                pass
