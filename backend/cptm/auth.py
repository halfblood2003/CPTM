"""Auth dependency: simple static token."""
import os

from fastapi import Header, HTTPException

TOKEN = os.environ.get("CPTM_TOKEN", "change-me")


async def require_token(x_cptm_token: str = Header(default="")) -> None:
    if x_cptm_token != TOKEN:
        raise HTTPException(status_code=401, detail="invalid or missing token")
