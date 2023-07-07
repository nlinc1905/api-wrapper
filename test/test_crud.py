import unittest
import os
from datetime import datetime
from sqlalchemy.exc import IntegrityError

from src.config.db import Base, engine, session_maker
from src.schemas import UserCreate, UserUpdate
from src.data_models import (
    User as UserModel,
    UserRequest as UserRequestModel,
)
from src.security import password_context
from src.crud import (
    create_user,
    create_request,
    update_user_self,
    get_user_by_username,
    get_user_requests,
    get_yearmon_requests,
)


# remove the DB and rebuild it for these tests
DB_NAME = "openai_wrapper_app.db"
if os.path.exists(DB_NAME):
    os.remove(DB_NAME)
# create the DB tables and relationships
Base.metadata.create_all(engine)


class TestCrud(unittest.TestCase):

    def setUp(self):
        self.session = session_maker()
        self.user = UserModel(
            username="whiterose",
            email="whiterose@ecorp.com",
            full_name="white rose",
            hashed_password=password_context.hash("password"),
            disabled=False,
        )
        self.user_create = UserCreate(
            username="whiterose",
            email="whiterose@ecorp.com",
            full_name="white rose",
            password="password",
            disabled=False,
        )
        self.user_request = UserRequestModel(
            timestamp=datetime(2012, 12, 21),
            user_id=1,
            prompt="test",
            cost=3.50,
            openai_response_code=200,
        )
        self.user_update = UserUpdate(
            username="whiterose",
            email="test@test.com",
            full_name="white rose",
            password="password",
            disabled=False,
        )

    def test_create_user(self):
        db_user = create_user(db=self.session, user=self.user_create)
        qres = self.session.query(UserModel).filter_by(username="whiterose").first()
        assert qres.email == "whiterose@ecorp.com"
        assert qres == db_user

    def test_create_request(self):
        db_request = create_request(db=self.session, request=self.user_request)
        qres = self.session.query(UserRequestModel).filter_by(user_id=1).first()
        assert qres == db_request

    def test_update_user_self(self):
        db_user = update_user_self(
            db=self.session,
            current_user=self.user,
            user_update=self.user_update
        )
        qres = self.session.query(UserModel).filter_by(username="whiterose").first()
        assert db_user.email != self.user.email
        assert qres.email == db_user.email

    def test_get_user_by_username(self):
        db_user = get_user_by_username(db=self.session, username="whiterose")
        assert db_user.username == "whiterose"

    def test_get_user_requests(self):
        user_req = get_user_requests(db=self.session, username="whiterose")
        assert len(user_req) > 0

    def test_get_yearmon_requests(self):
        yearmon_req = get_yearmon_requests(db=self.session,  year="2012", month="12")
        assert len(yearmon_req) > 0

    def tearDown(self):
        self.session.close()
