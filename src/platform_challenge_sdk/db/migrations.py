from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class MigrationError(Exception):
    pass


async def run_startup_migrations(challenge_name: str, version: str, dsn_encrypted: str) -> None:
    """Run automatic database migrations on startup.
    
    Checks schema_migrations table to avoid re-applying migrations that were
    already executed by platform-api or previous runs.
    """
    dsn = os.getenv("SDK_DB_DSN")
    if not dsn:
        raise MigrationError("Missing decrypted DB DSN")

    if version.isdigit():
        major = int(version)
    else:
        raise MigrationError("Invalid database version")
    if major < 1 or major > 16:
        raise MigrationError("Database version out of range (1..16)")

    target_db = f"{challenge_name}.v{major}"
    migrations_dir = f"db/migrations/v{major}"
    if not os.path.exists(migrations_dir):
        logger.debug(f"No migrations directory found: {migrations_dir}")
        return

    migration_files = sorted([f for f in os.listdir(migrations_dir) if f.endswith((".sql", ".py"))])
    if not migration_files:
        logger.debug(f"No migration files found in {migrations_dir}")
        return

    # Ensure migrations table exists
    await _ensure_migrations_table(target_db, dsn)

    # Get already applied migrations
    applied_migrations = await _get_applied_migrations(target_db, dsn)
    applied_map = {m["version"]: m for m in applied_migrations}

    logger.info(
        f"Found {len(applied_migrations)} already applied migrations, "
        f"{len(migration_files)} migration files to check"
    )

    # Process each migration file
    for migration_file in migration_files:
        migration_path = os.path.join(migrations_dir, migration_file)
        
        # Extract version from filename (e.g., "001_create_agents.sql" -> "001_create_agents")
        migration_version = Path(migration_file).stem
        
        # Calculate checksum
        checksum = await _calculate_migration_checksum(migration_path)
        
        # Check if migration was already applied
        if migration_version in applied_map:
            existing = applied_map[migration_version]
            if existing["checksum"] == checksum:
                logger.debug(
                    f"Migration {migration_version} already applied "
                    f"(checksum: {checksum[:8]}...), skipping"
                )
                continue
            else:
                logger.warning(
                    f"Migration {migration_version} has different checksum. "
                    f"Existing: {existing['checksum'][:8]}..., New: {checksum[:8]}... "
                    f"This may indicate the migration file was modified."
                )
                # Continue to re-apply (platform-api behavior: skip on mismatch)
                # But log warning for visibility
                continue

        # Apply migration
        logger.info(f"Applying migration {migration_version} (checksum: {checksum[:8]}...)")
        try:
            if migration_file.endswith(".sql"):
                await _apply_sql_migration(target_db, dsn, migration_path)
            elif migration_file.endswith(".py"):
                await _apply_python_migration(target_db, dsn, migration_path)
            
            # Record migration
            migration_name = migration_file
            await _record_migration(target_db, dsn, migration_version, migration_name, checksum)
            logger.info(f"Successfully applied and recorded migration {migration_version}")
        except Exception as e:
            logger.error(f"Failed to apply migration {migration_version}: {e}")
            raise MigrationError(f"Migration {migration_version} failed: {e}") from e

    await asyncio.sleep(0)
    return


async def _ensure_migrations_table(schema_name: str, dsn: str) -> None:
    """Ensure schema_migrations table exists in the schema."""
    create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {schema_name}.schema_migrations (
            version VARCHAR(255) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            checksum VARCHAR(64) NOT NULL
        )
    """
    
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        try:
            # Set search path to schema
            await conn.execute(f"SET search_path TO {schema_name}, public")
            await conn.execute(create_table_sql)
        finally:
            await conn.close()
    except ImportError:
        import psycopg2
        conn = psycopg2.connect(dsn)
        try:
            with conn.cursor() as cur:
                cur.execute(f"SET search_path TO {schema_name}, public")
                cur.execute(create_table_sql)
            conn.commit()
        finally:
            conn.close()


async def _get_applied_migrations(schema_name: str, dsn: str) -> list[dict[str, str]]:
    """Get list of already applied migrations from schema_migrations table."""
    query_sql = f"""
        SELECT version, name, applied_at, checksum
        FROM {schema_name}.schema_migrations
        ORDER BY version
    """
    
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(f"SET search_path TO {schema_name}, public")
            rows = await conn.fetch(query_sql)
            return [
                {
                    "version": row["version"],
                    "name": row["name"],
                    "applied_at": str(row["applied_at"]),
                    "checksum": row["checksum"],
                }
                for row in rows
            ]
        finally:
            await conn.close()
    except ImportError:
        import psycopg2
        conn = psycopg2.connect(dsn)
        try:
            with conn.cursor() as cur:
                cur.execute(f"SET search_path TO {schema_name}, public")
                cur.execute(query_sql)
                rows = cur.fetchall()
                return [
                    {
                        "version": row[0],
                        "name": row[1],
                        "applied_at": str(row[2]),
                        "checksum": row[3],
                    }
                    for row in rows
                ]
        finally:
            conn.close()
    except Exception as e:
        # If table doesn't exist yet, return empty list
        logger.debug(f"Could not query migrations table (may not exist yet): {e}")
        return []


async def _calculate_migration_checksum(migration_path: str) -> str:
    """Calculate SHA256 checksum of migration file."""
    with open(migration_path, "rb") as f:
        file_content = f.read()
    return hashlib.sha256(file_content).hexdigest()


async def _record_migration(
    schema_name: str, dsn: str, version: str, name: str, checksum: str
) -> None:
    """Record applied migration in schema_migrations table."""
    try:
        import asyncpg
        insert_sql = f"""
            INSERT INTO {schema_name}.schema_migrations (version, name, checksum, applied_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (version) DO UPDATE SET
                name = EXCLUDED.name,
                checksum = EXCLUDED.checksum,
                applied_at = EXCLUDED.applied_at
        """
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute(f"SET search_path TO {schema_name}, public")
            await conn.execute(insert_sql, version, name, checksum)
        finally:
            await conn.close()
    except ImportError:
        import psycopg2
        insert_sql = f"""
            INSERT INTO {schema_name}.schema_migrations (version, name, checksum, applied_at)
            VALUES (%s, %s, %s, NOW())
            ON CONFLICT (version) DO UPDATE SET
                name = EXCLUDED.name,
                checksum = EXCLUDED.checksum,
                applied_at = EXCLUDED.applied_at
        """
        conn = psycopg2.connect(dsn)
        try:
            with conn.cursor() as cur:
                cur.execute(f"SET search_path TO {schema_name}, public")
                cur.execute(insert_sql, (version, name, checksum))
            conn.commit()
        finally:
            conn.close()


async def _apply_sql_migration(target_db: str, dsn: str, migration_path: str) -> None:
    """Apply SQL migration file to database."""
    try:
        import asyncpg

        with open(migration_path) as f:
            sql = f.read()
        conn = await asyncpg.connect(dsn)
        try:
            # Set search path to schema
            await conn.execute(f"SET search_path TO {target_db}, public")
            await conn.execute(sql)
        finally:
            await conn.close()
    except ImportError:
        import psycopg2

        with open(migration_path) as f:
            sql = f.read()
        conn = psycopg2.connect(dsn)
        try:
            with conn.cursor() as cur:
                cur.execute(f"SET search_path TO {target_db}, public")
                cur.execute(sql)
            conn.commit()
        finally:
            conn.close()


async def _apply_python_migration(target_db: str, dsn: str, migration_path: str) -> None:
    """Apply Python migration module to database."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("migration", migration_path)
    if spec is None or spec.loader is None:
        raise MigrationError(f"Could not load migration: {migration_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if hasattr(module, "migrate"):
        migrate_func = module.migrate
        if asyncio.iscoroutinefunction(migrate_func):
            await migrate_func(target_db, dsn)
        else:
            migrate_func(target_db, dsn)
