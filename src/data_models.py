from sqlalchemy import (
    ForeignKey, Column, Integer, Float, Boolean, String, Text, DateTime,
)
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from src.config.db import Base, engine


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement="auto")
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)


class UserRequest(Base):
    __tablename__ = "user_requests"

    id = Column(Integer, primary_key=True, autoincrement="auto")
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    prompt = Column(Text)
    cost = Column(Float)
    openai_response_code = Column(Integer)

    user = relationship("User")


User.requests = relationship("UserRequest", order_by=UserRequest.id, back_populates="user")
