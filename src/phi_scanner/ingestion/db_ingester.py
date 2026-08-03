"""Lightweight read-only database ingester.

Allows users to pass a local database URI or SQLite file path (e.g. ``sqlite:///data.db``
or ``sqlite:///:memory:``) to scan entire database tables line-by-line in strict
READ-ONLY mode without altering or writing any data.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterator

from .base import CellRecord, SourceLocation


class DbIngester:
    """Read-only database ingester for local SQL databases (SQLite, DB-API)."""

    def ingest(self, connection_uri_or_path: str | Path) -> Iterator[tuple[str, SourceLocation]]:
        for record in self.ingest_records(connection_uri_or_path):
            yield record.text, record.location

    def ingest_records(self, connection_uri_or_path: str | Path) -> Iterator[CellRecord]:
        path_str = str(connection_uri_or_path)

        # Parse SQLite URI or direct file path
        if path_str.startswith("sqlite:///"):
            db_file = path_str.replace("sqlite:///", "")
        else:
            db_file = path_str

        db_path = Path(db_file)
        if not db_path.exists() and db_file != ":memory:":
            return

        # Open in strict read-only mode using URI format
        uri_conn_str = f"file:{db_path.resolve()}?mode=ro" if db_file != ":memory:" else ":memory:"
        try:
            conn = sqlite3.connect(uri_conn_str, uri=True)
        except Exception:
            try:
                conn = sqlite3.connect(db_file)
            except Exception:
                return

        try:
            cursor = conn.cursor()
            # Fetch all user tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
            tables = [r[0] for r in cursor.fetchall()]

            for table in tables:
                cursor.execute(f"PRAGMA table_info('{table}');")
                columns = [col[1] for col in cursor.fetchall()]

                cursor.execute(f"SELECT * FROM '{table}';")
                row_idx = 1
                while True:
                    rows = cursor.fetchmany(500)
                    if not rows:
                        break
                    for row in rows:
                        row_ctx = " ".join(str(val) for val in row if val is not None)
                        for col_idx, val in enumerate(row):
                            if val is None:
                                continue
                            val_str = str(val).strip()
                            if not val_str:
                                continue
                            col_name = columns[col_idx] if col_idx < len(columns) else f"col_{col_idx+1}"
                            loc = SourceLocation(file_path=db_path, sheet_name=table, row=row_idx, column=col_name)
                            yield CellRecord(text=val_str, location=loc, row_context=row_ctx)
                        row_idx += 1
        finally:
            conn.close()
