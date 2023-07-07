import typing as t
from sqlalchemy.orm import Session
from datetime import datetime
from dateutil.relativedelta import relativedelta

from src.data_models import (
    User as UserModel,
    UserRequest as UserRequestModel,
)
from src.schemas import (
    User,
    UserCreate,
    UserUpdate,
    UserRequest
)
from src.security import password_context


def create_user(db: Session, user: UserCreate) -> UserModel:
    """Creates a new user in the DB"""
    hashed_password = password_context.hash(user.password)
    db_user = UserModel(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        disabled=user.disabled,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user_by_username(db: Session, username: str) -> UserModel:
    """Gets user by username"""
    return db.query(UserModel).filter(UserModel.username == username).first()


def update_user_self(db: Session, current_user: User, user_update: UserUpdate) -> UserModel:
    """Updates a user's data in the DB"""
    db_user = get_user_by_username(db, current_user.username)
    db_user.username = user_update.username
    db_user.email = user_update.email
    db_user.full_name = user_update.full_name
    db_user.hashed_password = password_context.hash(user_update.password)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_request(db: Session, request: UserRequest) -> UserRequestModel:
    """Creates a new user request in the DB"""
    db_user_request = UserRequestModel(
        timestamp=request.timestamp,
        user_id=request.user_id,
        prompt=request.prompt,
        cost=request.cost,
        openai_response_code=request.openai_response_code,
    )
    db.add(db_user_request)
    db.commit()
    db.refresh(db_user_request)
    return db_user_request


def get_user_requests(db: Session,  username: str) -> t.List[UserRequestModel]:
    """Get the AI chat requests made by a user"""
    user_res = db.query(UserModel).filter(UserModel.username == username).first()
    if user_res is None:
        return []
    else:
        user_id = user_res.id
        res = db.query(UserRequestModel).filter(UserRequestModel.user_id == user_id).all()
        return res


def get_yearmon_requests(db: Session,  year: str, month: str) -> t.List[UserRequestModel]:
    """Get the AI chat requests made by a user"""
    year = int(year)
    month = int(month)
    target_month = datetime(year, month, 1)
    next_month = target_month + relativedelta(months=+1)
    res = db.query(UserRequestModel).filter(UserRequestModel.timestamp.between(target_month, next_month)).all()
    return res
