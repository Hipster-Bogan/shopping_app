"""Database helpers and table metadata for the shopping app."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Tuple

from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
    text,
    update,
)
from sqlalchemy.engine import Engine

DEFAULT_SQLITE_FILENAME = "shopping.db"


def resolve_sqlite_path(filename: str = DEFAULT_SQLITE_FILENAME) -> Path:
    """Return the filesystem path to the SQLite database file."""

    custom_file = os.environ.get("DATABASE_FILE")
    if custom_file:
        db_path = Path(custom_file).expanduser()
    else:
        base_dir = os.environ.get("APP_STATE_DIR") or os.environ.get("DATA_DIR")
        if base_dir:
            db_path = Path(base_dir).expanduser() / filename
        else:
            db_path = Path(__file__).resolve().parent / filename

    if not db_path.parent.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)

    return db_path


def _sqlite_url_from_path(path: Path) -> str:
    return f"sqlite:///{path}"


def normalise_database_url(database_url: str | None) -> Tuple[str, Dict]:
    """Normalise the configured database URL and return creation kwargs."""

    if database_url and database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    if not database_url:
        database_url = _sqlite_url_from_path(resolve_sqlite_path())

    if database_url.startswith("sqlite:///"):
        sqlite_path = database_url.replace("sqlite:///", "", 1)
        if sqlite_path.startswith(os.sep):
            sqlite_url = database_url
        else:
            sqlite_url = _sqlite_url_from_path(resolve_sqlite_path(sqlite_path))
        return sqlite_url, {"connect_args": {"check_same_thread": False}}

    return database_url, {}


def create_engine_from_url(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine for the provided database URL."""

    url, kwargs = normalise_database_url(database_url)
    return create_engine(url, future=True, **kwargs)


metadata = MetaData()

users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("email", String(255), unique=True, nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("is_admin", Boolean, nullable=False, default=False),
    Column("is_approved", Boolean, nullable=False, default=False),
)

lists_table = Table(
    "lists",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False),
    Column("token", String(32), unique=True, nullable=False),
)

list_items_table = Table(
    "list_items",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("list_id", Integer, ForeignKey("lists.id"), nullable=False),
    Column("item", String(255), nullable=False),
    Column("quantity", Integer, nullable=False, default=1),
    Column("checked", Boolean, nullable=False, default=False),
)


engine = create_engine_from_url(os.environ.get("DATABASE_URL"))

metadata.create_all(engine)


def ensure_schema(db_engine: Engine) -> None:
    """Ensure legacy boolean columns exist and are populated."""

    dialect = db_engine.dialect.name
    false_literal = "0" if dialect == "sqlite" else "FALSE"
    true_literal = "1" if dialect == "sqlite" else "TRUE"

    with db_engine.begin() as conn:
        inspector = inspect(conn)
        columns = {col["name"] for col in inspector.get_columns("users")}

        if "is_admin" not in columns:
            conn.execute(
                text(
                    f"ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT {false_literal}"
                )
            )

        if "is_approved" not in columns:
            conn.execute(
                text(
                    f"ALTER TABLE users ADD COLUMN is_approved BOOLEAN NOT NULL DEFAULT {false_literal}"
                )
            )
            conn.execute(text(f"UPDATE users SET is_approved = {true_literal}"))

    with db_engine.begin() as conn:
        conn.execute(
            update(users_table)
            .where(users_table.c.is_admin.is_(None))
            .values(is_admin=False)
        )
        conn.execute(
            update(users_table)
            .where(users_table.c.is_approved.is_(None))
            .values(is_approved=True)
        )

