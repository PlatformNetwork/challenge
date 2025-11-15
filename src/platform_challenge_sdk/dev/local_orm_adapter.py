"""Local ORM adapter for dev mode that uses SQLAlchemy directly."""

import logging
from typing import Any

from ..orm.client import Aggregation, ColumnValue, OrderBy, ORMQuery, QueryFilter, QueryResult
from ..orm.permissions import ORMPermissions

logger = logging.getLogger(__name__)


class LocalORMAdapter:
    """Local ORM adapter that uses SQLAlchemy directly in dev mode.

    This adapter bypasses WebSocket and uses direct database connections.
    """

    def __init__(
        self,
        db_manager: Any,  # SQLAlchemyManager instance
        permissions: ORMPermissions,
        challenge_id: str,
        schema_name: str,
    ):
        """Initialize local ORM adapter.

        Args:
            db_manager: SQLAlchemyManager instance
            permissions: ORM permissions instance
            challenge_id: Challenge ID
            schema_name: Schema name for this challenge
        """
        self.db_manager = db_manager
        self.permissions = permissions
        self.challenge_id = challenge_id
        self.schema_name = schema_name

    def _serialize_row(self, row: dict) -> dict:
        """Serialize a row dict, converting datetime and other non-JSON-serializable types."""
        import json
        from datetime import datetime, date
        from decimal import Decimal
        from uuid import UUID

        serialized = {}
        for key, value in row.items():
            if isinstance(value, (datetime, date)):
                # Convert datetime/date to ISO format string
                serialized[key] = value.isoformat()
            elif isinstance(value, Decimal):
                # Convert Decimal to float
                serialized[key] = float(value)
            elif isinstance(value, UUID):
                # Convert UUID to string
                serialized[key] = str(value)
            elif isinstance(value, (dict, list)):
                # Recursively serialize nested dicts/lists
                try:
                    # Try to serialize as-is (might already be JSON)
                    json.dumps(value)
                    serialized[key] = value
                except (TypeError, ValueError):
                    # If not JSON-serializable, try to convert
                    serialized[key] = json.loads(json.dumps(value, default=str))
            else:
                serialized[key] = value
        return serialized

    async def execute_query(self, query: ORMQuery) -> QueryResult:
        """Execute an ORM query using SQLAlchemy directly.

        Args:
            query: ORM query to execute

        Returns:
            QueryResult with rows and metadata
        """
        import time
        from sqlalchemy import text, Table, MetaData, inspect, bindparam
        from sqlalchemy.sql import select

        start_time = time.time()
        schema_prefix = f'"{self.schema_name}".' if self.schema_name else ""
        table_name = f'{schema_prefix}"{query.table}"'

        async with self.db_manager.get_session() as session:
            try:
                if query.operation == "select":
                    # Build SELECT query
                    columns_str = "*"
                    if query.columns:
                        columns_str = ", ".join(f'"{col}"' for col in query.columns)

                    sql = f"SELECT {columns_str} FROM {table_name}"

                    # Add WHERE clause
                    where_parts = []
                    params = {}
                    param_counter = 0
                    bindparams = []
                    for filt in query.filters:
                        if filt.operator.upper() in ("IN", "NOT IN"):
                            # Handle IN/NOT IN with list expansion using bindparam
                            if not isinstance(filt.value, list):
                                raise ValueError(f"{filt.operator} operator requires a list value")
                            if not filt.value:
                                # Empty list: IN () is always false, NOT IN () is always true
                                if filt.operator.upper() == "IN":
                                    where_parts.append("1=0")  # Always false
                                else:
                                    where_parts.append("1=1")  # Always true
                            else:
                                # Use bindparam with expanding=True for proper list handling
                                param_name = f"param_{param_counter}"
                                bindparams.append(bindparam(param_name, expanding=True))
                                params[param_name] = filt.value
                                where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                                param_counter += 1
                        elif filt.operator == "=":
                            param_name = f"param_{param_counter}"
                            where_parts.append(f'"{filt.column}" = :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1
                        elif filt.operator == "!=":
                            param_name = f"param_{param_counter}"
                            where_parts.append(f'"{filt.column}" != :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1
                        else:
                            param_name = f"param_{param_counter}"
                            where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1

                    if where_parts:
                        sql += " WHERE " + " AND ".join(where_parts)

                    # Add ORDER BY
                    if query.order_by:
                        order_parts = []
                        for order in query.order_by:
                            order_parts.append(f'"{order.column}" {order.direction}')
                        sql += " ORDER BY " + ", ".join(order_parts)

                    # Add LIMIT and OFFSET
                    if query.limit:
                        sql += f" LIMIT {query.limit}"
                    if query.offset:
                        sql += f" OFFSET {query.offset}"

                    # Create text() with bindparams if we have any
                    if bindparams:
                        stmt = text(sql).bindparams(*bindparams)
                    else:
                        stmt = text(sql)
                    result = await session.execute(stmt, params)
                    rows_raw = [dict(row._mapping) for row in result]
                    # Serialize rows to make them JSON-serializable
                    rows = [self._serialize_row(row) for row in rows_raw]
                    execution_time = int((time.time() - start_time) * 1000)

                    return QueryResult(
                        rows=rows, row_count=len(rows), execution_time_ms=execution_time
                    )

                elif query.operation == "count":
                    # Build COUNT query
                    sql = f"SELECT COUNT(*) as count FROM {table_name}"

                    where_parts = []
                    params = {}
                    param_counter = 0
                    bindparams = []
                    for filt in query.filters:
                        if filt.operator.upper() in ("IN", "NOT IN"):
                            # Handle IN/NOT IN with list expansion using bindparam
                            if not isinstance(filt.value, list):
                                raise ValueError(f"{filt.operator} operator requires a list value")
                            if not filt.value:
                                # Empty list: IN () is always false, NOT IN () is always true
                                if filt.operator.upper() == "IN":
                                    where_parts.append("1=0")  # Always false
                                else:
                                    where_parts.append("1=1")  # Always true
                            else:
                                # Use bindparam with expanding=True for proper list handling
                                param_name = f"param_{param_counter}"
                                bindparams.append(bindparam(param_name, expanding=True))
                                params[param_name] = filt.value
                                where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                                param_counter += 1
                        elif filt.operator == "=":
                            param_name = f"param_{param_counter}"
                            where_parts.append(f'"{filt.column}" = :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1
                        else:
                            param_name = f"param_{param_counter}"
                            where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1

                    if where_parts:
                        sql += " WHERE " + " AND ".join(where_parts)

                    # Create text() with bindparams if we have any
                    if bindparams:
                        stmt = text(sql).bindparams(*bindparams)
                    else:
                        stmt = text(sql)
                    result = await session.execute(stmt, params)
                    row = result.fetchone()
                    count = row[0] if row else 0
                    execution_time = int((time.time() - start_time) * 1000)

                    return QueryResult(
                        rows=[{"count": count}], row_count=1, execution_time_ms=execution_time
                    )

                elif query.operation == "insert":
                    # Build INSERT query
                    if not query.values:
                        raise ValueError("INSERT requires values")

                    import json

                    columns = [cv.column for cv in query.values]
                    values_list = []
                    jsonb_columns = {
                        "metadata",
                        "validation_errors",
                        "complexity_metrics",
                        "security_patterns",
                        "llm_validation_result",
                        "metrics",
                    }  # Common JSONB columns

                    for cv in query.values:
                        # Convert dict/list to JSON string for JSONB columns
                        if cv.column in jsonb_columns and isinstance(cv.value, (dict, list)):
                            values_list.append(json.dumps(cv.value))
                        else:
                            values_list.append(cv.value)

                    # Handle JSONB columns - cast to JSONB
                    columns_str = ", ".join(f'"{col}"' for col in columns)
                    placeholders = []
                    for i, col in enumerate(columns):
                        if col in jsonb_columns:
                            placeholders.append(f"CAST(:val_{i} AS JSONB)")
                        else:
                            placeholders.append(f":val_{i}")

                    placeholders_str = ", ".join(placeholders)
                    params = {f"val_{i}": val for i, val in enumerate(values_list)}

                    sql = f"INSERT INTO {table_name} ({columns_str}) VALUES ({placeholders_str}) RETURNING *"

                    result = await session.execute(text(sql), params)
                    row = result.fetchone()
                    inserted_row_raw = dict(row._mapping) if row else {}
                    # Serialize to make JSON-serializable
                    inserted_row = self._serialize_row(inserted_row_raw) if inserted_row_raw else {}
                    execution_time = int((time.time() - start_time) * 1000)

                    return QueryResult(
                        rows=[inserted_row], row_count=1, execution_time_ms=execution_time
                    )

                elif query.operation == "update":
                    # Build UPDATE query
                    if not query.set_values:
                        raise ValueError("UPDATE requires set_values")

                    set_parts = []
                    params = {}
                    for i, cv in enumerate(query.set_values):
                        param_name = f"set_{i}"
                        set_parts.append(f'"{cv.column}" = :{param_name}')
                        params[param_name] = cv.value

                    sql = f'UPDATE {table_name} SET {", ".join(set_parts)}'

                    # Add WHERE clause
                    where_parts = []
                    param_counter = len(params)  # Continue from set params
                    bindparams = []
                    for filt in query.filters:
                        if filt.operator.upper() in ("IN", "NOT IN"):
                            # Handle IN/NOT IN with list expansion using bindparam
                            if not isinstance(filt.value, list):
                                raise ValueError(f"{filt.operator} operator requires a list value")
                            if not filt.value:
                                # Empty list: IN () is always false, NOT IN () is always true
                                if filt.operator.upper() == "IN":
                                    where_parts.append("1=0")  # Always false
                                else:
                                    where_parts.append("1=1")  # Always true
                            else:
                                # Use bindparam with expanding=True for proper list handling
                                param_name = f"where_{param_counter}"
                                bindparams.append(bindparam(param_name, expanding=True))
                                params[param_name] = filt.value
                                where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                                param_counter += 1
                        elif filt.operator == "=":
                            param_name = f"where_{param_counter}"
                            where_parts.append(f'"{filt.column}" = :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1
                        else:
                            param_name = f"where_{param_counter}"
                            where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1

                    if where_parts:
                        sql += " WHERE " + " AND ".join(where_parts)

                    sql += " RETURNING *"

                    # Create text() with bindparams if we have any
                    if bindparams:
                        stmt = text(sql).bindparams(*bindparams)
                    else:
                        stmt = text(sql)
                    result = await session.execute(stmt, params)
                    rows_raw = [dict(row._mapping) for row in result]
                    # Serialize rows to make them JSON-serializable
                    rows = [self._serialize_row(row) for row in rows_raw]
                    execution_time = int((time.time() - start_time) * 1000)

                    return QueryResult(
                        rows=rows, row_count=len(rows), execution_time_ms=execution_time
                    )

                elif query.operation == "delete":
                    # Build DELETE query
                    sql = f"DELETE FROM {table_name}"

                    where_parts = []
                    params = {}
                    param_counter = 0
                    bindparams = []
                    for filt in query.filters:
                        if filt.operator.upper() in ("IN", "NOT IN"):
                            # Handle IN/NOT IN with list expansion using bindparam
                            if not isinstance(filt.value, list):
                                raise ValueError(f"{filt.operator} operator requires a list value")
                            if not filt.value:
                                # Empty list: IN () is always false, NOT IN () is always true
                                if filt.operator.upper() == "IN":
                                    where_parts.append("1=0")  # Always false
                                else:
                                    where_parts.append("1=1")  # Always true
                            else:
                                # Use bindparam with expanding=True for proper list handling
                                param_name = f"param_{param_counter}"
                                bindparams.append(bindparam(param_name, expanding=True))
                                params[param_name] = filt.value
                                where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                                param_counter += 1
                        elif filt.operator == "=":
                            param_name = f"param_{param_counter}"
                            where_parts.append(f'"{filt.column}" = :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1
                        else:
                            param_name = f"param_{param_counter}"
                            where_parts.append(f'"{filt.column}" {filt.operator} :{param_name}')
                            params[param_name] = filt.value
                            param_counter += 1

                    if where_parts:
                        sql += " WHERE " + " AND ".join(where_parts)
                    else:
                        # Safety: don't allow DELETE without WHERE
                        raise ValueError("DELETE without filters is not allowed")

                    # Create text() with bindparams if we have any
                    if bindparams:
                        stmt = text(sql).bindparams(*bindparams)
                    else:
                        stmt = text(sql)
                    result = await session.execute(stmt, params)
                    execution_time = int((time.time() - start_time) * 1000)

                    return QueryResult(
                        rows=[], row_count=result.rowcount or 0, execution_time_ms=execution_time
                    )

                else:
                    raise ValueError(f"Unsupported operation: {query.operation}")
            except Exception as e:
                logger.error(f"Error executing query: {e}", exc_info=True)
                raise

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
        query = ORMQuery(
            operation="select",
            table=table,
            columns=columns,
            filters=filters or [],
            order_by=order_by or [],
            limit=limit,
            offset=offset,
            schema=self.schema_name,
        )
        return await self.execute_query(query)

    async def count(self, table: str, filters: list[QueryFilter] | None = None) -> int:
        """Execute COUNT query."""
        query = ORMQuery(
            operation="count",
            table=table,
            filters=filters or [],
            schema=self.schema_name,
        )
        result = await self.execute_query(query)
        if result.rows and len(result.rows) > 0:
            if "count" in result.rows[0]:
                return result.rows[0]["count"]
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
            schema=self.schema_name,
        )
        return await self.execute_query(query)

    async def insert(self, table: str, values: dict[str, Any]) -> QueryResult:
        """Execute INSERT query."""
        column_values = [ColumnValue(column=k, value=v) for k, v in values.items()]
        query = ORMQuery(
            operation="insert",
            table=table,
            values=column_values,
            schema=self.schema_name,
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
            schema=self.schema_name,
        )
        return await self.execute_query(query)

    async def delete(self, table: str, filters: list[QueryFilter]) -> QueryResult:
        """Execute DELETE query."""
        query = ORMQuery(
            operation="delete",
            table=table,
            filters=filters,
            schema=self.schema_name,
        )
        return await self.execute_query(query)
