import os
import asyncio
import unittest
from fastapi.testclient import TestClient

# must remove the DB before importing from src.main, because that import will rebuild it
DB_NAME = "openai_wrapper_app.db"
if os.path.exists(DB_NAME):
    os.remove(DB_NAME)

from src.config.db import session_maker
from src.schemas import UserCreate
from src.crud import create_user
from src.main import app, base64_encode, num_tokens_from_string, get_openai_response


USERNAME = "whiterose"
PASSWORD = "password"
WRONG_PASSWORD = "wrong_password"
INACTIVE_USERNAME = "elliotalderson"
INACTIVE_PASSWORD = "secretpassword"

client = TestClient(app)


def set_up_test_db():
    """Sets up a SQLite session and populates the DB with data to use for these tests."""
    session = session_maker()

    # create users to use for tests
    # will not need to test creation endpoint because test_crud.py handles that
    user_create = UserCreate(
        username=USERNAME,
        email="whiterose@ecorp.com",
        full_name="white rose",
        password=PASSWORD,
        disabled=False,
    )
    disabled_user_create = UserCreate(
        username=INACTIVE_USERNAME,
        email="elliotalderson@ecorp.com",
        full_name="elliot alderson",
        password=INACTIVE_PASSWORD,
        disabled=True,
    )
    _ = create_user(user=user_create, db=session)
    _ = create_user(user=disabled_user_create, db=session)
    return


def user_authentication_headers(client: TestClient, username: str, password: str):
    data = {"username": username, "password": password}
    resp = client.post("/token", data=data)
    response = resp.json()
    auth_token = response["access_token"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    return headers


def test_base64_encode():
    string_to_encode = "test"
    enc_string = base64_encode(prompt=string_to_encode)
    assert enc_string == 'dGVzdA=='


def test_num_tokens_from_string():
    result = num_tokens_from_string(string="test")
    assert isinstance(result, int)


def test_get_openai_response():
    resp, cost = get_openai_response(prompt="test", prompt_type="chat")
    resp = repr(resp)
    assert cost >= 0
    assert len(resp) > 0


set_up_test_db()


class TestSecurityAsyncFunctions(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.username = USERNAME
        self.password = PASSWORD
        self.wrong_password = WRONG_PASSWORD
        self.inactive_username = INACTIVE_USERNAME
        self.inactive_password = INACTIVE_PASSWORD

    async def test_login_for_access_token(self):
        # test that a user receives a token (even inactive users can receive a token)
        response = client.post(
            "/token",
            data={
                "username": self.username,
                "password": self.password,
            },
            headers={"content-type": "application/x-www-form-urlencoded"}
        )
        assert response.status_code == 200
        assert len(response.json()['access_token']) > 0

        # test that an unauthenticated user receives an exception
        response = client.post(
            "/token",
            data={
                "username": self.username,
                "password": self.wrong_password,
            },
            headers={"content-type": "application/x-www-form-urlencoded"}
        )
        assert response.status_code == 401

    async def test_read_users_me(self):
        # test that an active user gets a response
        headers = user_authentication_headers(
            client=client,
            username=self.username,
            password=self.password
        )
        response = client.get("/users/me/", headers=headers)
        assert response.status_code == 200

        # test that an inactive user gets an exception
        headers = user_authentication_headers(
            client=client,
            username=self.inactive_username,
            password=self.inactive_password
        )
        response = client.get("/users/me/", headers=headers)
        assert response.status_code == 400

    async def test_respond(self):
        # test that an active user gets a response
        headers = user_authentication_headers(
            client=client,
            username=self.username,
            password=self.password
        )
        prompt = "test"
        response = client.get(f"/?prompt={prompt}", headers=headers)
        assert response.status_code == 200 or response.status_code == 503

        # test that an inactive user gets an exception
        headers = user_authentication_headers(
            client=client,
            username=self.inactive_username,
            password=self.inactive_password
        )
        prompt = "test"
        response = client.get(f"/?prompt={prompt}", headers=headers)
        assert response.status_code == 400
