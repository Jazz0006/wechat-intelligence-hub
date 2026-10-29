"""Compare timestamps as instants, including legacy local and ISO-offset rows."""

from __future__ import annotations

from datetime import datetime
import sqlite3


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).strip().replace("/", "-").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def timestamp_epoch(value: str | None) -> float | None:
    parsed = parse_timestamp(value)
    try:
        # Naive legacy rows use the host's local timezone, as the CLI did.
        return parsed.timestamp() if parsed is not None else None
    except (OverflowError, OSError, ValueError):
        return None


def local_timestamp(value: str | None) -> str:
    parsed = parse_timestamp(value)
    if parsed is None:
        return str(value or "").strip()
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed.isoformat(sep=" ", timespec="microseconds" if parsed.microsecond else "seconds")


def register_time_sql(conn: sqlite3.Connection) -> None:
    # No migration or UPDATE of old rows, hashes, or manually confirmed states.
    try:
        conn.execute("select message_epoch(NULL)").fetchall()
    except sqlite3.OperationalError as exc:
        if "no such function" not in str(exc):
            raise
        conn.create_function("message_epoch", 1, timestamp_epoch)


def validate_window(since: str, until: str) -> None:
    start, end = timestamp_epoch(since), timestamp_epoch(until)
    if start is None or end is None or start > end:
        raise ValueError("Invalid report time window; provide valid start and end timestamps.")
