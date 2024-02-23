import uuid

from sqlalchemy import Column, Integer, String, Boolean, UUID
from core.database import Base


class UserSchema(Base):
    __tablename__ = "users"

    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    username = Column(String)
    is_social_login = Column(Boolean, default=False)
    social_platform = Column(String)
    is_active = Column(Boolean, default=True)

