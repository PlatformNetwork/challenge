"""Server-side ORM adapter for use when challenge is a WebSocket server.

In server mode (CHALLENGE_ADMIN=true), the challenge runs as a WebSocket server
and platform-api connects to it. This adapter allows the challenge to use ORM
operations by sending messages through the MessageRouter.
"""

import asyncio
import logging
from typing import Any

from ..orm.client import Aggregation, ColumnValue, OrderBy, ORMQuery, QueryFilter, QueryResult
from ..orm.permissions import ORMPermissions

logger = logging.getLogger(__name__)


class ServerORMAdapter:
    """Server-side ORM adapter that uses MessageRouter for encrypted message handling.

    This adapter uses the MessageRouter to send ORM queries and receive responses,
    leveraging automatic encryption, decryption, and message correlation via IDs.
    """

    def __init__(
        self,
        router: Any,  # MessageRouter instance
        permissions: ORMPermissions,
        challenge_id: str,
    ):
        """Initialize server-side ORM adapter.

        Args:
            router: MessageRouter instance for sending/receiving encrypted messages
            permissions: ORM permissions instance
            challenge_id: Challenge ID for schema routing
        """
        self.router = router
        self.permissions = permissions
        self.challenge_id = challenge_id
        # Schema is ALWAYS set by platform-api - SDK does not store or use schema names

    async def execute_query(self, query: ORMQuery) -> QueryResult:
        """Execute an ORM query via the MessageRouter.

        Args:
            query: ORM query to execute

        Returns:
            QueryResult with rows and metadata
        """
        import uuid

        # DO NOT set schema here - platform-api will set it based on challenge configuration
        # The schema_name stored in adapter is for information only, not for query execution
        # Platform-api defines and controls schemas, SDK just sends the query as-is
        # Generate query ID for response matching
        # Use this as message_id so router can match it
        query_id = str(uuid.uuid4())

        # Create ORM query message
        # Platform-api expects: { "type": "orm_query", "payload": { "query": {...}, "query_id": "..." } }
        # We set message_id explicitly so router can match the response
        query_msg = {
            "type": "orm_query",
            "message_id": query_id,  # Set explicitly for router matching
            "payload": {
                "query": query.to_dict(),
                "query_id": query_id,  # Also include in payload for platform-api compatibility
            },
        }

        try:
            # Send via router (automatically encrypted) and wait for response
            response = await self.router.send_message(query_msg, timeout=30.0)

            # Extract result from response
            # Response format: { "type": "orm_result", "message_id": "...", "result": {...} }
            # or: { "type": "orm_result", "query_id": "...", "result": {...} }
            if response.get("type") == "orm_result":
                # Check both result locations
                result = response.get("result") or response.get("payload", {}).get("result")
                if result:
                    return QueryResult.from_dict(result)
                else:
                    raise Exception("orm_result response missing 'result' field")
            elif response.get("type") == "error":
                error_msg = response.get("error") or response.get("message", "Unknown error")
                raise Exception(f"ORM query error: {error_msg}")
            else:
                raise Exception(f"Unexpected response type: {response.get('type')}")

        except asyncio.TimeoutError as e:
            raise Exception(f"Timeout waiting for ORM query response: {e}") from e
        except Exception as e:
            # Check if it's a WebSocket connection error
            error_str = str(e)
            if "WebSocket" in error_str and (
                "not active" in error_str or "not connected" in error_str
            ):
                # WebSocket connection lost - provide helpful error message
                raise Exception(
                    f"WebSocket connection lost. The ORM service requires an active WebSocket connection. "
                    f"Please ensure the WebSocket connection is established and try again. Original error: {error_str}"
                ) from e
            # Re-raise other exceptions as-is
            raise

    async def handle_orm_result(self, query_id: str, response: dict[str, Any]) -> None:
        """Handle an incoming ORM result message (called from transport.ws).

        Note: This method is kept for compatibility but is no longer used
        since MessageRouter handles request/response matching automatically.

        Args:
            query_id: Query ID from the response
            response: Response message dict
        """
        # This method is deprecated - MessageRouter handles matching automatically
        logger.debug(
            f"handle_orm_result called for query_id={query_id} (MessageRouter handles this automatically)"
        )

    async def select(
        self,
        table: str,
        columns: list[str] | None = None,
        filters: list[QueryFilter] | None = None,
        order_by: list[OrderBy] | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> QueryResult:
        """Execute SELECT query."""
        # Do not set schema - platform-api will determine it
        query = ORMQuery(
            operation="select",
            table=table,
            columns=columns,
            filters=filters or [],
            order_by=order_by or [],
            limit=limit,
            offset=offset,
            schema=None,  # Platform-api will set the schema
        )
        return await self.execute_query(query)

    async def count(self, table: str, filters: list[QueryFilter] | None = None) -> int:
        """Execute COUNT query."""
        query = ORMQuery(
            operation="count",
            table=table,
            filters=filters or [],
            schema=None,  # Platform-api will set the schema
        )
        result = await self.execute_query(query)
        # COUNT returns row_count directly, but check if there's a count column
        if result.rows and len(result.rows) > 0:
            if "count" in result.rows[0]:
                return result.rows[0]["count"]
            # If no count column, use row_count
        return result.row_count if result.rows else 0

    async def aggregate(
        self,
        table: str,
        aggregations: list[Aggregation],
        filters: list[QueryFilter] | None = None,
        group_by: list[str] | None = None,
    ) -> QueryResult:
        """Execute aggregation query."""
        query = ORMQuery(
            operation="aggregate",
            table=table,
            filters=filters or [],
            aggregations=aggregations,
            group_by=group_by or [],
            schema=None,  # Platform-api will set the schema
        )
        return await self.execute_query(query)

    async def insert(self, table: str, values: dict[str, Any]) -> QueryResult:
        """Execute INSERT query."""
        column_values = [ColumnValue(column=k, value=v) for k, v in values.items()]
        query = ORMQuery(
            operation="insert",
            table=table,
            values=column_values,
            schema=None,  # Platform-api will set the schema
        )
        return await self.execute_query(query)

    async def update(
        self, table: str, set_values: dict[str, Any], filters: list[QueryFilter]
    ) -> QueryResult:
        """Execute UPDATE query."""
        column_values = [ColumnValue(column=k, value=v) for k, v in set_values.items()]
        query = ORMQuery(
            operation="update",
            table=table,
            set_values=column_values,
            filters=filters,
            schema=None,  # Platform-api will set the schema
        )
        return await self.execute_query(query)

    async def delete(self, table: str, filters: list[QueryFilter]) -> QueryResult:
        """Execute DELETE query."""
        query = ORMQuery(
            operation="delete",
            table=table,
            filters=filters,
            schema=None,  # Platform-api will set the schema
        )
        return await self.execute_query(query)
