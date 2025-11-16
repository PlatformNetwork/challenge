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




async def serve_ws(websocket, path: str, quote_provider) -> None:
    from starlette.websockets import WebSocketDisconnect

    try:
        # 1) Await attestation_begin
        # FastAPI/Starlette WebSocket API uses receive_text() instead of recv()
        begin_raw = await websocket.receive_text()
        begin = json.loads(begin_raw)
        if begin.get("type") != "attestation_begin":
            return

        nonce_hex = begin["nonce"]
        val_x25519_pub_b64 = begin["val_x25519_pub"]

        nonce = bytes.fromhex(nonce_hex)
        report_data = hashlib.sha256(nonce).digest()[:32]

        # Log that nonce was received (but not the actual data)
        import logging

        logging.info(f"Nonce received: {len(nonce_hex)} chars (hex)")
        logging.info("Report_data calculated from nonce (32 bytes)")

        # 2) Generate challenge X25519 keypair and quote
        chal_sk = secrets.token_bytes(32)
        chal_pub = crypto_scalarmult_base(chal_sk)

        # Check dev mode
        import os

        dev_mode = os.getenv("SDK_DEV_MODE", "").lower() == "true"

        quote, event_log, rtmrs = await quote_provider(report_data)

        # Validate quote before sending - must not be empty (unless dev mode)
        quote_len = len(quote) if quote else 0
        if not quote or quote_len < 100:
            import logging

            if dev_mode:
                # In dev mode, generate a fake quote if provider returned empty
                logging.warning("🔧 DEV MODE: Quote provider returned empty, generating fake quote")
                quote = secrets.token_bytes(1024)
                if not event_log:
                    event_log = '{"dev_mode": true}'
                if not rtmrs:
                    rtmrs = {}
            else:
                logging.error(
                    f"Quote is empty or too short ({quote_len} bytes), closing WebSocket connection"
                )
                return

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
            logging.info("🔧 DEV MODE: Using encrypted session with mock TDX attestation")
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
            logging.info("🚀 Queue worker started - ready to send messages via WebSocket")
            message_count = 0
            while True:
                try:
                    # Wait for message to send (already encrypted JSON string)
                    msg = await outgoing_queue.get()
                    if msg is None:  # Sentinel to stop
                        logging.info(f"🛑 Queue worker stopping (sent {message_count} messages)")
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
                                f"📤 Queue worker: Sending encrypted message #{message_count}"
                            )
                        else:
                            logging.info(
                                f"📤 Queue worker: Sending message #{message_count} type={msg_type} id={msg_id}"
                            )
                    except Exception:
                        # If we can't parse for logging, just send it
                        logging.debug(
                            f"📤 Queue worker: Sending message #{message_count} (non-JSON or encrypted)"
                        )

                    await websocket.send_text(msg)
                    outgoing_queue.task_done()
                    logging.debug(f"✅ Queue worker: Message #{message_count} sent successfully")
                except Exception as e:
                    logging.error(
                        f"❌ Queue worker error sending message #{message_count}: {e}",
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

            logging.info("✅ Received migrations_request, processing...")

            # Get DB version from challenge registry
            from ..challenge.decorators import challenge

            db_version = challenge.db_version or 1  # Default to 1 if not set
            logging.info(f"DB version: {db_version}")

            migrations = []
            migrations_dir = "db/migrations/v1"

            # hashlib and os are already imported at the top of the file
            if os.path.exists(migrations_dir):
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
                logging.warning(f"Migrations directory {migrations_dir} does not exist")

            # Send migrations_response with db_version
            await router.send_push_message(
                {
                    "type": "migrations_response",
                    "message_id": msg.get("message_id"),  # Include original message_id
                    "payload": {"migrations": migrations, "db_version": db_version},
                }
            )
            logging.info(
                f"Sending migrations_response: {len(migrations)} migrations, db_version={db_version}"
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
            logging.info("✅ Received orm_ready signal from platform-api")

            # Platform-api sends schema name in orm_ready, but SDK does not store it
            # Platform-api will set the schema for each ORM query - SDK just sends queries without schema
            schema_name = msg.get("schema") or (
                msg.get("payload", {}).get("schema")
                if isinstance(msg.get("payload"), dict)
                else None
            )
            if schema_name:
                logging.info(
                    f"📋 Platform-api schema: {schema_name} (SDK will not store or use this)"
                )
            else:
                logging.warning(
                    "⚠️ orm_ready signal missing schema name (non-fatal, platform-api will set schema per query)"
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
                        f"✅ Server-side ORM adapter initialized for challenge {challenge_id} (schema managed by platform-api)"
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
                    logging.info("📤 Sending ORM permissions to platform-api...")

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
                        f"✅ ORM permissions sent for challenge {challenge_id} ({len(permissions_dict)} tables)"
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
                    logging.info("🧪 Calling registered on_orm_ready handler...")
                    handler = challenge.orm_ready_handler
                    if asyncio.iscoroutinefunction(handler):
                        # Schedule handler to run in background
                        asyncio.create_task(handler())
                    else:
                        # Run synchronously if not async
                        handler()
                else:
                    logging.debug("No on_orm_ready handler registered (this is optional)")
            except Exception as e:
                logging.error(f"Failed to call on_orm_ready handler: {e}", exc_info=True)

        async def handle_orm_result(msg: dict) -> None:
            """Handle orm_result messages - responses from platform-api for server-side ORM queries."""
            # Extract query_id or message_id for routing
            query_id = msg.get("query_id") or msg.get("message_id")

            if query_id:
                logging.info(f"📥 Received orm_result with query_id={query_id}")
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

        # Register all handlers
        router.register_handler("migrations_request", handle_migrations_request)
        router.register_handler("db_version_request", handle_db_version_request)
        router.register_handler("orm_ready", handle_orm_ready)
        router.register_handler("orm_result", handle_orm_result)
        router.register_handler("job_execute", handle_job_execute)

        # Assign router to challenge registry for global access
        try:
            from ..challenge.decorators import challenge

            challenge.message_router = router
            # Store send_task reference for health checks (optional - mainly for debugging)
            router._send_task = send_task  # type: ignore
            router._websocket_active = True  # type: ignore
            logging.info("✅ MessageRouter initialized and assigned to challenge registry")
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
                    "⚠️ WebSocket disconnected by client - ORM queries will fail until reconnected"
                )
                # Mark router as inactive
                try:
                    from ..challenge.decorators import challenge

                    if hasattr(challenge, "message_router") and challenge.message_router:
                        challenge.message_router._websocket_active = False  # type: ignore
                except Exception:
                    # Failed to update router state, non-critical during disconnect
                    pass
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
