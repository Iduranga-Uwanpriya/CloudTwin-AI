"""
Database session management.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

def _build_database_url():
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    # Build from separate env vars (avoids special chars breaking URL)
    user = os.getenv("DB_USER", "cloudtwin")
    password = os.getenv("DB_PASSWORD", "cloudtwin_secret")
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    name = os.getenv("DB_NAME", "cloudtwin_db")
    from urllib.parse import quote_plus
    return f"postgresql://{user}:{quote_plus(password)}@{host}:{port}/{name}"

DATABASE_URL = _build_database_url()

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
