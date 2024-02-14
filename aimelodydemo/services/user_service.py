from datetime import datetime, timedelta
from typing import Union
from urllib import parse
from uuid import UUID

from fastapi import HTTPException, status
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from jose import JWTError, jwt
from passlib.context import CryptContext
from pytz import timezone
from sqlalchemy.orm import Session

from aimelodydemo.core.config import get_settings
from aimelodydemo.core.schemas import UserSchema
from aimelodydemo.models.user_model import User, UserCreate


# ------------------------------------------------------------------
# 계정 생성 파트
# ------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    global pwd_context
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password) -> bool:
    global pwd_context
    return pwd_context.verify(plain_password, hashed_password)

def create_user(db: Session, user: UserCreate) -> UserSchema:
    if get_user_by_email(db, user.email) != None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Email already registered")
    
    secret_key: str = get_settings().secret_key
    db_user = UserSchema(
        email=user.email,
        password=None if user.is_social_login else get_password_hash(user.password),
        first_name=user.first_name,
        last_name=user.last_name,
        username=user.username,
        is_social_login=user.is_social_login,
        social_platform=user.social_platform,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_user_by_id(db: Session, user_id: UUID) -> Union[UserSchema, None]:
    return db.query(UserSchema).filter(UserSchema.id == user_id).first()

def get_user_by_email(db: Session, user_email: str) -> Union[UserSchema, None]:
    return db.query(UserSchema).filter(UserSchema.email == user_email).first()


# ------------------------------------------------------------------
# 인증 및 토큰 생성 파트
# ------------------------------------------------------------------
def authenticate_user(db: Session, email: str, passwowrd: str) -> Union[UserSchema, None]:
    """
    if email and password is matched with db, return True.
    else, return false
    """
    user = get_user_by_email(db, email)
    if user == None:
        return None
    if not verify_password(passwowrd, user.password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone('Asia/Seoul')) + expires_delta
    else:
        expire = datetime.now(timezone('Asia/Seoul')) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    print(to_encode)
    encoded_jwt = jwt.encode(
        to_encode,
        get_settings().secret_key,
        algorithm=get_settings().algorithm
    )
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone('Asia/Seoul')) + expires_delta
    else:
        expire = datetime.now(timezone('Asia/Seoul')) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    print(to_encode)
    encoded_jwt = jwt.encode(
        to_encode,
        get_settings().jwt_secret_key,
        algorithm=get_settings().jwt_algorithm
    )
    return encoded_jwt


authorize_endpoint = "http://localhost:8000/api/users/auth/google/callback/"
flow = Flow.from_client_config(
    client_config={
       "web": {
           "client_id": get_settings().google_client_id,
            "client_secret": get_settings().google_secret_pw,
            "redirect_uris": [authorize_endpoint],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://accounts.google.com/o/oauth2/token",
        },
    },
    scopes=["https://www.googleapis.com/auth/userinfo.email","openid"]
)
flow.redirect_uri = authorize_endpoint

def get_redirection_url_to_google_auth():
    return flow.authorization_url()[0]

def get_email_from_google_code(code: str):
    # credentiall added to flow
    # https://github.com/googleapis/google-api-python-client/blob/main/docs/oauth.md
    flow.fetch_token(code=parse.unquote(code))
    credentials = flow.credentials
    user_info_service = build('oauth2', 'v2', credentials=credentials)
    user_info = user_info_service.userinfo().get().execute()
    print(user_info['email'])
