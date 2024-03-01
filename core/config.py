from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    AWS_COGNITO_USER_POOL_ID: str
    AWS_COGNITO_CLIENT_ID: str
    AWS_COGNITO_CLIENT_SECRET: str 
    sqlalchemy_database_url: str
    google_client_id: str
    google_secret_pw: str
    jwt_secret_key: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    refresh_token_expire_days: int

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_settings():
    """
    설정값을 .env로부터 읽어오고, 객체 형태로 리턴한다.
    lru_cache 데코레이터를 적용하여 실행 횟수를 줄인다.
    """
    return Settings()
