from typing import Union
from typing_extensions import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, status, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from aimelodydemo.core.dependencies import get_db
from aimelodydemo.models.user_model import User, UserCreate, JWTToken
from aimelodydemo.services.user_service import (
    create_user,
    get_user_by_email,
    authenticate_user,
    create_access_token,
    get_redirection_url_to_google_auth,
    get_email_from_google_code,
)


router = APIRouter(
    prefix="/api/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)


@router.get("/{email}", response_model=User)
def get_user(email: str, db: Session = Depends(get_db)):
    user_info = get_user_by_email(db, email)
    if user_info == None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
    return user_info

@router.post("/auth/register", response_model=User, status_code=status.HTTP_201_CREATED)
def register_user(
    email: Annotated[str, Form()],
    first_name: Annotated[str, Form()],
    last_name: Annotated[str, Form()],
    username: Annotated[str, Form()],
    is_socail_login: Annotated[bool, Form()],
    social_platform: Annotated[Union[str, None], Form()] = None,
    password: Annotated[Union[str, None], Form()] = None,
    db: Session = Depends(get_db)
):
    if is_socail_login and (social_platform == None or password != None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Do not contain socila_platform and password for social register"
        )
    elif not is_socail_login and (social_platform != None or password == None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Contain social_platform and password for common register"
        )
    
    user_info = UserCreate(
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        username=username,
        is_social_login=is_socail_login,
        social_platform=social_platform,
    )
    return create_user(db, user_info)
    

@router.post("/auth/login")
def login_for_access_token(
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, email, password)
    if user == None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"}, # 공부해볼 것
        )
    access_token = create_access_token(
        data={"uuid": str(user.id)}
    )
    return JWTToken(access_token=access_token, token_type="bearer")


@router.get("/auth/google")
def redirect_to_google_oauth():
    url = get_redirection_url_to_google_auth()
    return RedirectResponse(url)

@router.get("/auth/google/callback/")
def google_oauth_callback(code: str):
    get_email_from_google_code(code)
