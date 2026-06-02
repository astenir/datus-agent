"""Models for API authentication endpoints."""

from typing import List

from pydantic import BaseModel, Field


class LoginInput(BaseModel):
    """Username/password login request for RBAC auth provider."""

    username: str = Field(..., min_length=1, description="Configured user name")
    password: str = Field(..., min_length=1, description="User password")


class LoginData(BaseModel):
    """Bearer token returned by RBAC login."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user_id: str
    roles: List[str] = Field(default_factory=list)
