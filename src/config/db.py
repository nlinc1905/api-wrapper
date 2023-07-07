import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


ENV = os.getenv("ENV", default="test")
if ENV == "test":
    DB_NAME = "openai_wrapper_app.db"
    SQL_DATABASE_URL = f"sqlite:///./{DB_NAME}"
else:
    SQL_DATABASE_URL = "postgresql://admin:password@postgresdb/db"


engine = create_engine(SQL_DATABASE_URL)
session_maker = sessionmaker(bind=engine, expire_on_commit=False, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    """Establishes a SQLite session"""
    db = session_maker()
    try:
        yield db
    finally:
        db.close()
