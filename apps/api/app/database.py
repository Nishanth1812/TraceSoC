from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool

from .config import get_settings
from .schema import metadata


def create_database_engine(database_url: str | None = None) -> Engine:
    """Create a PostgreSQL or SQLite engine from the configured URL.

    SQLite is intentionally supported as a local/test persistence backend.  A
    StaticPool keeps an in-memory database available across FastAPI's request
    connections while PostgreSQL retains the normal pooled behavior.
    """

    url = database_url or get_settings().database_url
    if url.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        if url in {"sqlite://", "sqlite:///:memory:"}:
            return create_engine(
                url,
                connect_args=connect_args,
                poolclass=StaticPool,
            )
        return create_engine(url, connect_args=connect_args, pool_pre_ping=True)
    return create_engine(url, pool_pre_ping=True)


engine = create_database_engine()


def initialize_schema(database_engine: Engine | None = None) -> None:
    """Create the application tables for a local SQLite database.

    PostgreSQL deployments should use ``alembic upgrade head``.  SQLite has no
    separate service in the test/dev path, so creating the portable schema is
    a convenient and explicit local setup operation.
    """

    selected_engine = database_engine or engine
    metadata.create_all(selected_engine)


def database_is_healthy() -> bool:
    """Return whether the configured database accepts a trivial query."""

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return False
    return True


def get_connection() -> Generator:
    """Yield a database connection for future route dependencies."""

    with engine.begin() as connection:
        yield connection
