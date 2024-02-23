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
from models.user_model import User, UserCreate, Token, AccessRefreshTokenPair
from services.user_service import (
    create_user,
    get_user_by_email,
    get_user_by_id,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    get_redirection_url_to_google_auth,
    get_email_from_google_code,
)


router = APIRouter(
    prefix="/api/user",
    tags=["user"],
    responses={404: {"description": "Not found"}},
)


@router.get("/me", response_model=User)
def get_current_user(user_id: str = Depends(validate_access_token), db: Session = Depends(get_db)):
    user_info = get_user_by_id(db, UUID(user_id))
    if user_info == None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
    return user_info

@router.get("/{email}", response_model=User)
def get_user(email: str, db: Session = Depends(get_db)):
    user_info = get_user_by_email(db, email)
    if user_info == None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
    return user_info


@router.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
def register_user(
    user: UserCreate = Depends(UserCreate.as_form),
    db: Session = Depends(get_db)
):
    if user.is_social_login and (user.social_platform == None or user.password != None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Do not contain socila_platform and password for social register"
        )
    elif not user.is_social_login and (user.social_platform != None or user.password == None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Contain social_platform and password for common register"
        )
    
    return create_user(db, user)
    

@router.post("/login")
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
    # User를 요구하지만 UserSchema 넘겼습니다.
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    
    return AccessRefreshTokenPair(
        access_token=Token(token=access_token, token_type="access"),
        refresh_token=Token(token=refresh_token, token_type="refresh")
    )


@router.get("/social-login/google")
def redirect_to_google_oauth():
    url = get_redirection_url_to_google_auth()
    return RedirectResponse(url)

@router.get("/social-login/google/callback/")
def google_oauth_callback(code: str):
    get_email_from_google_code(code)
