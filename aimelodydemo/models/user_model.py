from uuid import UUID
from typing import Union

from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    first_name: str
    last_name: str
    username: str

class UserCreate(UserBase):
    password: Union[str, None]
    is_social_login: bool
    social_platform: Union[str, None]

class User(UserBase):
    id: UUID
    is_active: bool
    class Config:
        from_attributes = True

class JWTToken(BaseModel):
    access_token: str
    token_type: str

