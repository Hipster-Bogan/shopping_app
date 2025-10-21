"""One-off helper to migrate data from SQLite to PostgreSQL."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable, Sequence

from sqlalchemy import delete, insert, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from database import (
    create_engine_from_url,
    ensure_schema,
    list_items_table,
    lists_table,
    metadata,
    resolve_sqlite_path,
    users_table,
)

TABLES_IN_INSERT_ORDER: Sequence = (users_table, lists_table, list_items_table)


def _normalise_source(value: str | None) -> str:
    if not value:
        return f"sqlite:///{resolve_sqlite_path()}"

    if "://" in value:
        return value

    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return f"sqlite:///{path}"


def _destination_url(value: str | None) -> str:
    if value:
        return value

    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url

    raise SystemExit("Destination database URL must be provided via --destination or DATABASE_URL")


def _ensure_destination_empty(engine: Engine, force: bool) -> None:
    populated_tables = []

    with engine.connect() as conn:
        for table in TABLES_IN_INSERT_ORDER:
            row = conn.execute(select(table.c.id).limit(1)).first()
            if row is not None:
                populated_tables.append(table.name)

    if populated_tables and not force:
        joined = ", ".join(populated_tables)
        raise SystemExit(
            "Destination already contains data in: {}. Pass --force to overwrite.".format(joined)
        )

    if populated_tables and force:
        with engine.begin() as conn:
            for table in reversed(TABLES_IN_INSERT_ORDER):
                conn.execute(delete(table))


def _fetch_table_rows(engine: Engine, table) -> list[dict]:
    with engine.connect() as conn:
        result = conn.execute(select(table).order_by(table.c.id)).mappings()
        return [dict(row) for row in result]


def _copy_rows(source: Engine, destination: Engine) -> None:
    payload = {table.name: _fetch_table_rows(source, table) for table in TABLES_IN_INSERT_ORDER}

    with destination.begin() as conn:
        for table in TABLES_IN_INSERT_ORDER:
            rows = payload[table.name]
            if rows:
                conn.execute(insert(table), rows)


def _reset_postgres_sequences(engine: Engine) -> None:
    if engine.dialect.name != "postgresql":
        return

    sequence_statements = {
        "users": "users_id_seq",
        "lists": "lists_id_seq",
        "list_items": "list_items_id_seq",
    }

    with engine.begin() as conn:
        for table in TABLES_IN_INSERT_ORDER:
            sequence = sequence_statements.get(table.name)
            if not sequence:
                continue

            conn.execute(
                text(
                    "SELECT setval(:sequence, COALESCE((SELECT MAX(id) FROM "
                    + table.name
                    + "), 0) + 1, false)"
                ),
                {"sequence": sequence},
            )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        help="SQLite path or connection URL. Defaults to the local development SQLite file.",
    )
    parser.add_argument(
        "--destination",
        help="PostgreSQL connection URL. Falls back to DATABASE_URL environment variable.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite destination data if tables already contain rows.",
    )

    args = parser.parse_args(argv)

    source_url = _normalise_source(args.source)
    destination_url = _destination_url(args.destination)

    try:
        source_engine = create_engine_from_url(source_url)
        destination_engine = create_engine_from_url(destination_url)
    except SQLAlchemyError as exc:
        raise SystemExit(f"Failed to initialise database engines: {exc}") from exc

    metadata.create_all(destination_engine)
    ensure_schema(destination_engine)

    _ensure_destination_empty(destination_engine, args.force)

    try:
        _copy_rows(source_engine, destination_engine)
        _reset_postgres_sequences(destination_engine)
    except SQLAlchemyError as exc:
        raise SystemExit(f"Migration failed: {exc}") from exc

    print("Migration complete. Rows copied:")
    for table in TABLES_IN_INSERT_ORDER:
        count = len(_fetch_table_rows(destination_engine, table))
        print(f"  {table.name}: {count}")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main())

