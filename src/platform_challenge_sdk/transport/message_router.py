"""Message Router for centralized WebSocket message handling with encryption and correlation IDs."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class MessageRouter:
    """
    Centralized message router for WebSocket communication.

    Handles:
    - Automatic encryption/decryption via AeadSession
    - Request/response correlation via unique message IDs
    - Concurrent message handling with asyncio.Future
    - Type-based message routing with registered handlers
    - Timeout management for pending requests
    """

    def __init__(
        self,
        session: Any,  # AeadSession
        outgoing_queue: asyncio.Queue,
    ):
        """
        Initialize MessageRouter.

        Args:
            session: AeadSession instance for encryption/decryption
            outgoing_queue: Queue for thread-safe message sending (receives JSON strings of encrypted envelopes)
        """
        self._session = session
        self._outgoing_queue = outgoing_queue
        self._pending_requests: dict[str, asyncio.Future] = {}
        self._message_id_counter = 0
        self._type_handlers: dict[str, list[Callable]] = defaultdict(list)
        self._running = True

    def register_handler(self, msg_type: str, handler: Callable[[dict], Any]) -> None:
        """
        Register a handler for a specific message type.

        Handlers receive decrypted messages and can be async or sync.

        Args:
            msg_type: Message type (e.g., "orm_ready", "migrations_request")
            handler: Handler function (async or sync) that takes a decrypted message dict
        """
        self._type_handlers[msg_type].append(handler)
        logger.debug(f"Registered handler for message type: {msg_type}")

    def _generate_message_id(self) -> str:
        """Generate a unique message ID for request/response correlation."""
        self._message_id_counter += 1
        return f"msg_{self._message_id_counter}_{uuid.uuid4().hex[:8]}"

    async def send_message(
        self,
        message: dict[str, Any],
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """
        Send a message and wait for response with automatic encryption.

        The message is automatically encrypted, sent via the queue, and the response
        is automatically decrypted before being returned.

        Args:
            message: Message dict to send (will be encrypted)
            timeout: Timeout in seconds (default: 30.0)

        Returns:
            Decrypted response message dict

        Raises:
            asyncio.TimeoutError: If no response received within timeout
            Exception: If response contains an error
        """
        # Check if WebSocket is still active (health check)
        if hasattr(self, "_websocket_active") and not self._websocket_active:
            raise Exception("WebSocket connection is not active - cannot send message. The WebSocket may have been disconnected. Please check the connection status.")

        # Check if send task is still running (health check)
        if hasattr(self, "_send_task"):
            if self._send_task.done():
                # Check if task completed with an error
                try:
                    self._send_task.result()  # This will raise if task had an exception
                except Exception as e:
                    raise Exception(f"WebSocket send task failed: {e}") from e
                raise Exception("WebSocket send task has stopped - connection may be broken")

        # Generate message ID if not already present
        # This allows callers (like ORM queries) to set their own message_id
        if "message_id" not in message:
            message_id = self._generate_message_id()
            message["message_id"] = message_id
        else:
            message_id = message["message_id"]

        # Create future for response
        future = asyncio.Future()
        self._pending_requests[message_id] = future

        try:
            # Verify queue is still available (should always be, but check for safety)
            if self._outgoing_queue is None:
                raise Exception("Outgoing queue is None - router may have been closed")

            # Encrypt message
            encrypted_envelope = self._session.encrypt(message)
            encrypted_json = json.dumps(encrypted_envelope)

            # Send via queue (will be handled by worker in transport/ws.py)
            logger.info(
                f"📤 Putting message in queue: ID={message_id}, type={message.get('type')}, queue_size={self._outgoing_queue.qsize()}"
            )
            await self._outgoing_queue.put(encrypted_json)
            logger.info(
                f"✅ Message put in queue successfully: ID={message_id}, type={message.get('type')}, new_queue_size={self._outgoing_queue.qsize()}"
            )

            logger.debug(
                f"Sent message with ID {message_id}, type={message.get('type')}, waiting for response..."
            )

            # Wait for response with timeout
            try:
                response = await asyncio.wait_for(future, timeout=timeout)

                # Check for errors in response
                if response.get("type") == "error":
                    error_msg = response.get("error", "Unknown error")
                    raise Exception(f"Message error: {error_msg}")

                return response

            except asyncio.TimeoutError:
                self._pending_requests.pop(message_id, None)
                raise asyncio.TimeoutError(
                    f"Message {message_id} (type={message.get('type')}) timed out after {timeout}s"
                ) from None

        except Exception:
            # Clean up on error
            self._pending_requests.pop(message_id, None)
            raise

    async def send_message_async(
        self,
        message: dict[str, Any],
    ) -> asyncio.Future:
        """
        Send a message and return a Future for the response.

        Useful for concurrent requests where you want to await multiple responses.
        The Future will contain the decrypted response message dict.

        Args:
            message: Message dict to send (will be encrypted)

        Returns:
            asyncio.Future that will resolve to the decrypted response dict
        """
        message_id = self._generate_message_id()
        message["message_id"] = message_id

        future = asyncio.Future()
        self._pending_requests[message_id] = future

        try:
            # Encrypt and send
            encrypted_envelope = self._session.encrypt(message)
            encrypted_json = json.dumps(encrypted_envelope)
            await self._outgoing_queue.put(encrypted_json)

            logger.debug(f"Sent async message with ID {message_id}, type={message.get('type')}")
            return future

        except Exception as e:
            # Clean up on error
            self._pending_requests.pop(message_id, None)
            future.set_exception(e)
            return future

    async def send_push_message(self, message: dict[str, Any]) -> None:
        """
        Send a push message (no response expected) with automatic encryption.

        Args:
            message: Message dict to send (will be encrypted)
        """
        # Push messages don't need a message_id unless they're responses
        # But we can add one for tracking/logging purposes
        if "message_id" not in message:
            message["message_id"] = self._generate_message_id()

        # Encrypt and send
        encrypted_envelope = self._session.encrypt(message)
        encrypted_json = json.dumps(encrypted_envelope)
        await self._outgoing_queue.put(encrypted_json)

        logger.debug(
            f"Sent push message with ID {message['message_id']}, type={message.get('type')}"
        )

    async def handle_incoming_message(self, encrypted_envelope: dict[str, Any]) -> None:
        """
        Handle an incoming encrypted message.

        Decrypts the message, routes it to registered handlers, and resolves
        pending futures for request/response matching.

        Args:
            encrypted_envelope: Encrypted message envelope dict with "enc", "nonce", "ciphertext"
        """
        try:
            # Decrypt message
            decrypted_msg = self._session.decrypt(encrypted_envelope)

            msg_type = decrypted_msg.get("type")
            message_id = decrypted_msg.get("message_id")

            # Also check for query_id in payload (for ORM queries compatibility)
            query_id = None
            if not message_id:
                query_id = decrypted_msg.get("query_id")
                # Also check nested in payload
                if not query_id and isinstance(decrypted_msg.get("payload"), dict):
                    query_id = decrypted_msg.get("payload", {}).get("query_id")
                if query_id:
                    message_id = query_id  # Use query_id as message_id for matching

            logger.debug(f"Handling incoming message: type={msg_type}, message_id={message_id}")

            # Check if this is a response to a pending request
            if message_id and message_id in self._pending_requests:
                future = self._pending_requests.pop(message_id)
                if not future.done():
                    future.set_result(decrypted_msg)
                    logger.debug(f"Resolved future for message_id={message_id}")
                else:
                    logger.warning(f"Future for message_id={message_id} already done")

            # Route to registered handlers (only if not a response to pending request)
            # If message_id was found in pending_requests, the future was already resolved
            # But we may still want to call handlers for logging/monitoring
            if msg_type:
                handlers = self._type_handlers.get(msg_type, [])

                # Call all registered handlers
                for handler in handlers:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            # Schedule async handler
                            asyncio.create_task(handler(decrypted_msg))
                        else:
                            # Call sync handler directly
                            handler(decrypted_msg)
                    except Exception as e:
                        logger.error(f"Error in handler for {msg_type}: {e}", exc_info=True)

            # If no handlers registered and not a response, log unhandled message
            if msg_type and message_id not in self._pending_requests:
                if not self._type_handlers.get(msg_type):
                    logger.debug(f"Unhandled message type: {msg_type} (no handlers registered)")

        except Exception as e:
            logger.error(f"Error handling incoming message: {e}", exc_info=True)

    def cleanup_expired_requests(self, timeout: float = 60.0) -> None:
        """
        Cleanup expired pending requests (for memory management).

        This should be called periodically to prevent memory leaks.

        Args:
            timeout: Maximum age for pending requests in seconds
        """
        # This is a simple implementation - in production, you might want
        # to track request timestamps for more accurate cleanup
        # For now, we rely on the timeout in send_message() to clean up

        expired_count = len([f for f in self._pending_requests.values() if f.done()])
        if expired_count > 0:
            # Remove done futures
            self._pending_requests = {
                mid: f for mid, f in self._pending_requests.items() if not f.done()
            }
            logger.debug(f"Cleaned up {expired_count} expired requests")

    async def close(self) -> None:
        """Close the router and clean up resources."""
        self._running = False

        # Cancel all pending requests
        for _message_id, future in self._pending_requests.items():
            if not future.done():
                future.cancel()

        self._pending_requests.clear()
        logger.info("MessageRouter closed")
