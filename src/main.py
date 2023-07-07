import os
import sys
import logging
import base64
import openai
import tiktoken
import typing as t
from datetime import datetime, timedelta
from fastapi import Depends, Request, FastAPI, Query, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing_extensions import Annotated
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from src.schemas import User, Token, UserCreate, UserUpdate, UserRequest
from src.security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    get_current_active_user,
)
from src.config.db import Base, engine, get_db
from src.crud import (
    create_user,
    update_user_self,
    get_user_by_username,
    create_request,
    get_user_requests,
    get_yearmon_requests,
)


logger = logging.getLogger()
log_level = os.environ.get("LOG_LEVEL", "DEBUG")
logger.setLevel(log_level)
if not logger.hasHandlers():
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "dummy")
if len(OPENAI_API_KEY) == 0:
    logger.error("No OpenAI API key environment variable provided.")
    sys.exit(1)
openai.api_key = OPENAI_API_KEY
MODEL = "gpt-3.5-turbo"
# get tokenizer from:
# https://github.com/openai/openai-cookbook/blob/main/examples/How_to_count_tokens_with_tiktoken.ipynb
MODEL_TOKENIZER = "cl100k_base"
# get model context len from:
# https://platform.openai.com/docs/models/gpt-3-5
MODEL_CONTEXT_LEN = 4096
MAX_COMPLETION_LEN = 250
# get price per 1,000 tokens from:
# https://openai.com/pricing
MODEL_COST_PER_1K_INPUT_TOKENS = 0.0015
MODEL_COST_PER_1K_OUTPUT_TOKENS = 0.002


# create the DB tables and relationships
Base.metadata.create_all(engine)


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="OpenAI Wrapper")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def base64_encode(prompt: str) -> str:
    """Compresses and encodes a request prompt"""
    b64_bytes = base64.b64encode(prompt.encode("ascii"))
    b64_str = b64_bytes.decode("ascii")
    return b64_str


def num_tokens_from_string(string: str, encoding_name: str = MODEL_TOKENIZER) -> int:
    """Returns the number of tokens in a text string."""
    encoding = tiktoken.get_encoding(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens


def get_openai_response(prompt: str, prompt_type: t.Literal["single", "chat"] = "chat"):
    """Gets prompt response from OpenAI language model."""

    # adjust prompt length if necessary
    chars_removed = 0
    chars_to_remove_per_iter = 100
    while num_tokens_from_string(prompt) > (MODEL_CONTEXT_LEN + MAX_COMPLETION_LEN):
        prompt = prompt[:-chars_to_remove_per_iter] + "."
        chars_removed += chars_to_remove_per_iter
    logger.warning(f"Removed {chars_removed} characters from the end of the prompt to stay within the token limit.")

    # estimate cost of the request
    request_tokens = num_tokens_from_string(prompt)
    input_cost = request_tokens / 1000 * MODEL_COST_PER_1K_INPUT_TOKENS
    output_cost = MAX_COMPLETION_LEN / 1000 * MODEL_COST_PER_1K_OUTPUT_TOKENS
    total_cost = input_cost + output_cost
    logger.info(f"Prompt tokens: {request_tokens}")
    logger.info(f"Cost for this request: ${total_cost:.2f}")

    # get response
    try:
        if prompt_type == "single":
            resp = openai.Completion.create(
                model=MODEL,
                prompt=prompt,
                temperature=0.7,
                max_tokens=250,
                top_p=1.0,
                frequency_penalty=0.0,
                presence_penalty=1
            )
            return resp["choices"][0]["text"]
        else:
            resp = openai.ChatCompletion.create(
                model=MODEL,
                n=1,
                top_p=1.0,
                frequency_penalty=0.0,
                presence_penalty=1,
                messages=[
                    {"role": "system", "content": "You are an expert in everything."},
                    {"role": "user", "content": prompt},
                ],
            )
            return resp["choices"][0]["message"]["content"], total_cost
    except Exception as e:
        # raise HTTPException(
        #     status_code=503,
        #     detail=f"Received the following error from OpenAI: {e}"
        # )
        total_cost = 0
        return e, total_cost


# TODO: need to lock down so only admins can create - would require adding roles and admin accounts
@app.post("/new_user", response_model=User)
def create_new_user(
    user: UserCreate,
    db: Session = Depends(get_db),
):
    """Creates a new user"""
    db_user = create_user(db, user)
    return db_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
):
    """Authenticates the user by checking the DB and provides an access token"""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def get_my_user_data(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """Gets the user data for an authenticated user"""
    return current_user


@app.put("/update_user", response_model=User)
def update_my_user_data(
    user_update: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Allows a user to update their own data"""
    db_user = update_user_self(db, current_user, user_update)
    return db_user


@app.get("/users/cost/{username}")
def get_ai_chat_requests_for_user(username: str, db: Session = Depends(get_db)):
    """Gets the historical record of OpenAI chat requests for a given user.  Does not require authentication."""
    user_requests = get_user_requests(db, username)
    return {"requests": user_requests}


@app.get("/cost/{year_month}")
def get_ai_chat_requests_for_year_month(yearmon: str, db: Session = Depends(get_db)):
    """
    Gets the historical record of OpenAI chat requests for all users in a given month.
    Does not require authentication.
    """
    if "-" not in yearmon or len(yearmon) != len("YYYY-MM"):
        raise HTTPException(
            status_code=422,
            detail="Improperly formatted year_month.  Please format as {YYYY-MM}",
        )
    year, month = yearmon.split("-")
    yearmon_requests = get_yearmon_requests(db, year, month)
    return {"requests": yearmon_requests}


@app.get("/", response_model=str)
@limiter.limit("3/minute")
async def ai_chat(
        request: Request,
        current_user: Annotated[User, Depends(get_current_active_user)],
        prompt: str = Query(...),
        db: Session = Depends(get_db),
):
    """Sends a chat prompt to OpenAI.  Requires authentication."""
    logger.info(f"Chat request from {current_user.username}")

    # prompt type must match the model type, for 3.5 turbo, it is 'chat' for example
    openai_resp, cost = get_openai_response(prompt, prompt_type="chat")

    # track the request
    user_id = int(get_user_by_username(db=db, username=current_user.username).id)
    request_data = {
        "timestamp": datetime.now(),  # .strftime("%Y-%b-%d %H:%m:%s"),
        "user_id": user_id,
        "prompt": base64_encode(prompt),
        "cost": float(cost),
        "openai_response_code": int(openai_resp.http_status),
    }
    user_request = UserRequest.parse_obj(request_data)
    _ = create_request(db, user_request)

    return openai_resp if isinstance(openai_resp, str) else repr(openai_resp)
