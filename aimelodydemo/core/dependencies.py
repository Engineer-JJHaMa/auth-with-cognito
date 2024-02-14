from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import jwt

from aimelodydemo.core.config import get_settings
from aimelodydemo.core.database import SessionLocal
from aimelodydemo.models.user_model import User, JWTToken

reusable_oauth = OAuth2PasswordBearer(
    tokenUrl="/login",
    scheme_name="JWT"
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# async def get_current_user(token: str = Depends(reusable_oauth)) -> User:
#         payload = jwt.decode(
#             token, get_settings().jwt_secret_key, algorithms=[get_settings().jwt_algorithm]
#         )
#         token = JWTToken(**payload)
        
#     pass