from typing import Union
from typing_extensions import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Form,
    Header,
    HTTPException,
    Query,
    Response,
    status
)
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from core.dependencies import validate_access_token, get_db
from models.user_model import (
    CodeDeliveryDetails,
    IsUserExists,
    UserRegsterCode,
    UserBase, UserCreate
)
from services.user_service import (
    check_user_exists,
    confirm_register_code,
    get_redirection_url_to_google_auth,
    get_token_from_aws_code,
    start_sign_in,
    start_sign_up,
)


router = APIRouter(
    prefix="/api/user",
    tags=["user"],
    responses={404: {"description": "Not found"}},
)


@router.get("/me", response_model=UserBase)
def get_current_user(user: UserBase = Depends(validate_access_token)):
    return user


@router.get("/is-user-exists", response_model=IsUserExists, status_code=status.HTTP_200_OK)
def get_user_exists(email: str):
    return check_user_exists(email)

@router.post("/sign-up", response_model=CodeDeliveryDetails, status_code=status.HTTP_201_CREATED)
def register_user(
    user: UserCreate = Depends(UserCreate.as_form),
):
    return start_sign_up(user)

@router.post("/sign-up/confirm", status_code=status.HTTP_200_OK)
def confim_register(user: UserRegsterCode):
    confirm_register_code(user)
    return "successfully confirmed"


@router.post("/login")
def login_for_access_token(
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
):
    return start_sign_in(email, password)


@router.get("/social-login/google")
def redirect_to_google_oauth():
    url = get_redirection_url_to_google_auth()
    return RedirectResponse(url)

@router.get("/social-login/google/callback")
def google_oauth_callback(code: str):
    return get_token_from_aws_code(code)
