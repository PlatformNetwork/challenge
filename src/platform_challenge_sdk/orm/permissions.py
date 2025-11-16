"""ORM Permissions system for defining readable tables and columns."""

from dataclasses import dataclass, field


@dataclass
class TablePermission:
    """Defines permissions for a single table."""

    table_name: str
    readable_columns: set[str] = field(default_factory=set)
    writable_columns: set[str] = field(default_factory=set)  # Columns validators can write
    allowed_operations: set[str] = field(default_factory=lambda: {"select", "count"})  # Default read-only
    allow_aggregations: bool = True
    max_rows: int | None = 10000

    def add_readable_columns(self, *columns: str) -> "TablePermission":
        """Add readable columns to this table permission."""
        self.readable_columns.update(columns)
        return self
    
    def add_columns(self, *columns: str) -> "TablePermission":
        """Alias for add_readable_columns for backwards compatibility."""
        return self.add_readable_columns(*columns)
    
    def add_writable_columns(self, *columns: str) -> "TablePermission":
        """Add writable columns to this table permission (for validators)."""
        self.writable_columns.update(columns)
        return self
    
    def allow_operations(self, *operations: str) -> "TablePermission":
        """Set allowed operations (select, count, insert, update, delete)."""
        self.allowed_operations = set(operations)
        return self

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "table_name": self.table_name,
            "readable_columns": list(self.readable_columns),
            "writable_columns": list(self.writable_columns),
            "allowed_operations": list(self.allowed_operations),
            "allow_aggregations": self.allow_aggregations,
            "max_rows": self.max_rows,
        }


class ORMPermissions:
    """Manages ORM permissions for challenge tables."""

    def __init__(self):
        self._permissions: dict[str, TablePermission] = {}
        self._initialize_default_permissions()

    def _initialize_default_permissions(self):
        """Initialize default permissions for common tables."""
        # Challenge submissions table
        self.add_table_permission(
            TablePermission("challenge_submissions").add_columns(
                "id",
                "validator_hotkey",
                "miner_hotkey",
                "block_height",
                "challenge_name",
                "challenge_version",
                "score",
                "weight",
                "status",
                "created_at",
                "started_at",
                "completed_at",
            )
        )

        # Miner performance table
        self.add_table_permission(
            TablePermission("miner_performance").add_columns(
                "id",
                "miner_hotkey",
                "epoch",
                "total_submissions",
                "successful_submissions",
                "failed_submissions",
                "average_score",
                "total_weight",
                "created_at",
                "updated_at",
            )
        )

        # Weight recommendations table
        self.add_table_permission(
            TablePermission("weight_recommendations", allow_aggregations=False).add_columns(
                "id",
                "epoch",
                "block_height",
                "total_miners",
                "active_miners",
                "submitted",
                "created_at",
                "submitted_at",
            )
        )

        # Challenge metrics table
        self.add_table_permission(
            TablePermission("challenge_metrics", max_rows=5000).add_columns(
                "id",
                "metric_name",
                "metric_type",
                "value",
                "window_start",
                "window_end",
                "created_at",
            )
        )

    def add_table_permission(self, permission: TablePermission) -> None:
        """Add or update permission for a table."""
        self._permissions[permission.table_name] = permission

    def remove_table_permission(self, table_name: str) -> None:
        """Remove permission for a table."""
        self._permissions.pop(table_name, None)

    def get_table_permission(self, table_name: str) -> TablePermission | None:
        """Get permission for a specific table."""
        return self._permissions.get(table_name)

    def can_read_table(self, table_name: str) -> bool:
        """Check if a table can be read."""
        return table_name in self._permissions

    def can_read_column(self, table_name: str, column_name: str) -> bool:
        """Check if a column can be read."""
        permission = self._permissions.get(table_name)
        if not permission:
            return False
        return column_name in permission.readable_columns

    def get_readable_tables(self) -> list[str]:
        """Get list of all readable tables."""
        return list(self._permissions.keys())

    def get_readable_columns(self, table_name: str) -> list[str]:
        """Get list of readable columns for a table."""
        permission = self._permissions.get(table_name)
        if not permission:
            return []
        return sorted(permission.readable_columns)

    def to_dict(self) -> dict[str, dict]:
        """Convert all permissions to dictionary for transmission."""
        return {table_name: perm.to_dict() for table_name, perm in self._permissions.items()}

    @classmethod
    def from_dict(cls, data: dict[str, dict]) -> "ORMPermissions":
        """Create ORMPermissions from dictionary."""
        permissions = cls()
        permissions._permissions.clear()  # Clear defaults

        for table_name, perm_data in data.items():
            permission = TablePermission(
                table_name=table_name,
                readable_columns=set(perm_data.get("readable_columns", [])),
                allow_aggregations=perm_data.get("allow_aggregations", True),
                max_rows=perm_data.get("max_rows"),
            )
            permissions.add_table_permission(permission)

        return permissions


# Decorator for marking SQLAlchemy models as readable
def readable_table(
    readable_columns: list[str], allow_aggregations: bool = True, max_rows: int | None = None
):
    """Decorator to mark a SQLAlchemy model as readable with specific permissions."""

    def decorator(cls):
        # Store permission metadata on the class
        cls.__readable_columns__ = readable_columns
        cls.__allow_aggregations__ = allow_aggregations
        cls.__max_rows__ = max_rows
        cls.__is_readable__ = True

        # Add class method to get permission
        @classmethod
        def get_table_permission(cls_) -> TablePermission:
            return TablePermission(
                table_name=cls_.__tablename__,
                readable_columns=set(cls_.__readable_columns__),
                allow_aggregations=cls_.__allow_aggregations__,
                max_rows=cls_.__max_rows__,
            )

        cls.get_table_permission = get_table_permission
        return cls

    return decorator


def extract_permissions_from_models(*model_classes) -> ORMPermissions:
    """Extract permissions from decorated SQLAlchemy models."""
    permissions = ORMPermissions()
    permissions._permissions.clear()  # Clear defaults

    for model_cls in model_classes:
        if hasattr(model_cls, "__is_readable__") and model_cls.__is_readable__:
            permission = model_cls.get_table_permission()
            permissions.add_table_permission(permission)

    return permissions
