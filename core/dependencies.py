import os

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


from jose import jwt

from core.config import get_settings
from core.database import SessionLocal
from models.user_model import AccessToken, UserBase
from services.user_service import get_user_by_token

access_scheme = HTTPBearer(scheme_name="Access")


def validate_access_token(
    credentials: HTTPAuthorizationCredentials = Depends(access_scheme)
) -> UserBase:
    """
    access token이 valid한지 체크하여 user id를 리턴
    """
    if credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme. Must use 'Bearer'."
        )
    user = get_user_by_token(AccessToken(token=credentials.credentials))
    return user

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
