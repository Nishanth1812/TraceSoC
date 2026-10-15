from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from .config import get_settings


def create_database_engine() -> Engine:
    settings = get_settings()
    return create_engine(settings.database_url, pool_pre_ping=True)


engine = create_database_engine()


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
