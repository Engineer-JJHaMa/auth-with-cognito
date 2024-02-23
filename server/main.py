from typing import Union
from typing_extensions import Annotated

from fastapi import FastAPI, status, Depends
import uvicorn
from pydantic import BaseModel

from core.dependencies import validate_access_token
from routes import user

app = FastAPI()

app.include_router(user.router)


def start():
    uvicorn.run(
        "server.main:app",
        port=443,
        reload=True,
        ssl_keyfile="/Users/hama_macbook/Desktop/side-project/practice/tutorial/AImelodyDemo/localhost+1-key.pem",
        ssl_certfile="/Users/hama_macbook/Desktop/side-project/practice/tutorial/AImelodyDemo/localhost+1.pem",
    )
