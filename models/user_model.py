from uuid import UUID
from typing import Union, Literal

from fastapi import Form
from pydantic import BaseModel

class UserBase(BaseModel):
    email: str
    name: str
    nickname: str

class UserCreate(UserBase):
    password: Union[str, None]

    @classmethod
    def as_form(
        self, 
        email: str = Form(...),
        name: str = Form(...),
        nickname: str = Form(...),
        password: str = Form(...),
    ):
        return self(
            email=email,
            name=name,
            nickname=nickname,
            password=password
        )

# class User(UserBase):
#     id: UUID
#     is_active: bool
#     class Config:
#         from_attributes = True


class AccessToken(BaseModel):
    token: str


class IsUserExists(BaseModel):
    email: str
    is_user_exists: bool
    is_user_confirmed: bool


class CodeDeliveryDetails(BaseModel):
    Destination: str
    DeliveryMedium: Literal["SMS", "EMAIL"]
    AttributeName: str


class UserRegsterCode(BaseModel):
    email: str
    code: str
