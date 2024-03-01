from urllib.parse import urlencode

from fastapi import HTTPException, status
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build


from core.config import get_settings
from models.user_model import (
    AccessToken,
    CodeDeliveryDetails,
    IsUserExists,
    UserBase,
    UserCreate,
    UserRegsterCode
)
from services.cognito_idp_wrapper import CognitoIdentityProviderWrapper

provider = CognitoIdentityProviderWrapper()



def check_user_exists(email: str) -> IsUserExists:
    """start-sign-up 이전에, 같은 이메일로 가입한 유저가 있는지 체크합니다."""
    try:
        return provider.check_user_exists(email)
    except:
        HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Error occured during the check"
        )


def start_sign_up(user: UserCreate) -> CodeDeliveryDetails:
    """sign-up을 시작합니다. UserCreate 정보를 바탕으로 유저를 유저 풀에 추가하고, 인증 메세지 전송 경로를 리턴합니다."""
    try:
        detail = provider.sign_up_user(user.email, user.password, user.name, user.nickname)
        print(detail)
        return detail
    except:
        HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Error occured during the register"
        )


def confirm_register_code(code: UserRegsterCode):
    try:
        provider.confirm_user_sign_up(code.email, code.code)
    except:
        HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Error occured during the register"
        )


def start_sign_in(email: str, password: str) -> AccessToken:
    try:
        AuthenticationResult = provider.start_sign_in(email, password)
    except:
        HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Error occured during the sign-in"
        )
    return AccessToken(token=AuthenticationResult["AccessToken"])


def get_user_by_token(token: AccessToken) -> UserBase:
    response = provider.get_user_by_token(token.token)
    userdata = {}
    for attr in response["UserAttributes"]:
        userdata[attr["Name"]] = attr["Value"]
    
    return UserBase(
        email=userdata["email"],
        name=userdata["name"],
        nickname=userdata["nickname"]
    )


google_auth_endpoint = "https://ai-melody-demo-dev.auth.ap-northeast-2.amazoncognito.com/oauth2/authorize"
params = {
    "identity_provider": "Google",
    "redirect_uri": "https://127.0.0.1/api/user/social-login/google/callback",
    "response_type": "code",
    "client_id": get_settings().AWS_COGNITO_CLIENT_ID,
    "scope": "email openid phone aws.cognito.signin.user.admin"
}
redirect_url = f"{google_auth_endpoint}?{urlencode(params)}"

def get_redirection_url_to_google_auth():
    print(redirect_url)
    return redirect_url


def get_token_from_aws_code(code: str):
    response = provider.get_access_token_with_aws_code(code)
    return AccessToken(token=response.json()["access_token"])
