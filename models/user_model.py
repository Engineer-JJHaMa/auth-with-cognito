from uuid import UUID
from typing import Union

from fastapi import Form
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

    @classmethod
    def as_form(
        self, 
        email: str = Form(...),
        first_name: str = Form(...),
        last_name: str = Form(...),
        username: str = Form(...),
        is_social_login: bool = Form(...),
        social_platform: Union[str, None] = Form(default=None),
        password: Union[str, None] = Form(default=None)
    ):
        return self(
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            is_social_login=is_social_login,
            social_platform=social_platform,
            password=password
        )

class User(UserBase):
    id: UUID
    is_active: bool
    class Config:
        from_attributes = True


class Token(BaseModel):
    token: str
    token_type: str


class AccessRefreshTokenPair(BaseModel):
    access_token: Token
    refresh_token: Token
