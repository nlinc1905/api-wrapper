import typing as t
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: t.Union[str, None] = None


class UserBase(BaseModel):
    username: str
    email: t.Union[str, None] = None
    full_name: t.Union[str, None] = None
    disabled: bool = False


class UserCreate(UserBase):
    password: str


class UserUpdate(UserBase):
    password: str


class User(UserBase):
    # disabled: t.Union[bool, None] = None
    hashed_password: str

    class Config:
        orm_mode = True


class UserRequest(BaseModel):
    timestamp: datetime
    user_id: int
    prompt: str
    cost: float
    openai_response_code: int
