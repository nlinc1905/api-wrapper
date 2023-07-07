import unittest
import asyncio
import time
import os
import typing as t
from datetime import timedelta
from passlib.exc import UnknownHashError
from fastapi import HTTPException

from src.config.db import Base, engine, session_maker
from src.crud import create_user
from src.security import (
    get_password_hash,
    verify_password,
    get_user,
    authenticate_user,
    create_access_token,
    get_current_user,
    get_current_active_user,
)
from src.schemas import User, UserCreate


# remove the DB and rebuild it for these tests
DB_NAME = "openai_wrapper_app.db"
if os.path.exists(DB_NAME):
    os.remove(DB_NAME)
# create the DB tables and relationships
Base.metadata.create_all(engine)

USERNAME = "whiterose"
PASSWORD = "password"


def set_up_test_db():
    """Sets up a SQLite session and populates the DB with data to use for these tests."""
    db_session = session_maker()

    # create users to use for tests
    # will not need to test creation endpoint because test_crud.py handles that
    user_create = UserCreate(
        username=USERNAME,
        email="whiterose@ecorp.com",
        full_name="white rose",
        password=PASSWORD,
        disabled=False,
    )
    _ = create_user(user=user_create, db=db_session)
    return db_session


session = set_up_test_db()


class TestSecurityFunctions(unittest.TestCase):

    def setUp(self):
        self.session = session
        self.username = USERNAME
        self.password = PASSWORD
        self.wrong_password = "wrong_password"
        self.not_a_hash = "not a hash"
        self.not_a_user = "notauser"

    def test_get_password_hash(self):
        password_hash = get_password_hash(self.password)
        assert isinstance(password_hash, str)
        assert len(password_hash) > 0

    def test_verify_password(self):
        # the function should fail if a string that is not a hash is passed
        self.assertRaises(UnknownHashError, verify_password, self.password, self.not_a_hash)

        # test that the correct hash-password combo succeeds
        hashed_password = get_password_hash(self.password)
        result1 = verify_password(self.password, hashed_password)
        assert result1

        # test that the wrong hash-password combo fails
        hashed_password = get_password_hash(self.wrong_password)
        result2 = verify_password(self.password, hashed_password)
        assert not result2

    def test_get_user(self):
        # test that a user in the DB returns a User instance
        user = get_user(self.session, self.username)
        assert isinstance(user, User)

        # test that a user that is not in the DB returns None
        user = get_user(self.session, self.not_a_user)
        assert user is None

    def test_authenticate_user(self):
        # test that a legitimate user can be authenticated
        result1 = authenticate_user(self.session, self.username, self.password)
        assert isinstance(result1, User)

        # test that an illegitimate user cannot be authenticated
        result2 = authenticate_user(self.session, self.not_a_user, self.password)
        assert isinstance(result2, bool)
        assert not result2

    def test_create_access_token(self):
        # test that a token gets created
        data = {"sub": self.username}
        expires_delta = timedelta(minutes=1)
        token_str = create_access_token(data, expires_delta)
        assert isinstance(token_str, str)
        assert len(token_str) > 0


class TestSecurityAsyncFunctions(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.session = session
        self.username = USERNAME
        self.password = PASSWORD
        self.wrong_password = "hacker"
        self.not_a_hash = "not a hash"
        self.not_a_user = "notauser"
        self.expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3aGl0ZXJvc2UiLCJleHAiOjE2ODg0MTA3MTl9.7RZbrcFpP-rBaBiEl0EaQm4lH23Sm4NHc4wS7LUcr44"
        self.inactive_username = "elliotalderson"

    async def test_get_current_user(self):
        # test that an authenticated user that is in the DB returns a User instance
        data = {"sub": self.username}
        expires_delta = timedelta(minutes=1)
        token_str = create_access_token(data, expires_delta)
        result = await get_current_user(token=token_str, db=self.session)
        assert isinstance(result, User)

        # test that an empty username returns a credentials exception
        data = {}
        expires_delta = timedelta(minutes=1)
        token_str = create_access_token(data, expires_delta)
        with self.assertRaises(HTTPException) as e:
            await get_current_user(token=token_str, db=self.session)
        assert isinstance(e.exception, HTTPException)

        # test that an expired token returns an expired signature error
        with self.assertRaises(HTTPException) as e:
            await get_current_user(token=self.expired_token, db=self.session)
        assert isinstance(e.exception, HTTPException)

        # test that an authenticated user that is not in the DB returns a credentials exception
        data = {"sub": self.not_a_user}
        expires_delta = timedelta(minutes=1)
        token_str = create_access_token(data, expires_delta)
        with self.assertRaises(HTTPException) as e:
            await get_current_user(token=token_str, db=self.session)
        assert isinstance(e.exception, HTTPException)

    async def test_get_current_active_user(self):
        # test that a currently active user has a User instance returned
        user = User(
            username=self.username,
            email="whiterose@ecorp.com",
            full_name="white rose",
            hashed_password=get_password_hash(self.password),
            disabled=False,
        )
        result = await get_current_active_user(user)
        assert isinstance(result, User)

        # test that an inactive user has an HTTPException returned
        user = User(
            username=self.inactive_username,
            email=f"{self.inactive_username}@ecorp.com",
            full_name=self.inactive_username,
            hashed_password=get_password_hash(self.password),
            disabled=True,
        )
        with self.assertRaises(HTTPException) as e:
            await get_current_active_user(user)
        assert isinstance(e.exception, HTTPException)
