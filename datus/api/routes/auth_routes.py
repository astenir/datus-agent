"""API routes for authentication."""

from fastapi import APIRouter, HTTPException, status

from datus.api.deps import AuthProviderDep
from datus.api.models.auth_models import LoginData, LoginInput
from datus.api.models.base_models import Result

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=Result[LoginData], summary="Login")
async def login(request: LoginInput, auth_provider: AuthProviderDep) -> Result[LoginData]:
    """Issue a bearer token when the configured auth provider supports login."""
    login_func = getattr(auth_provider, "login", None)
    if not callable(login_func):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The configured auth provider does not support username/password login.",
        )
    token_data = login_func(request.username, request.password)
    return Result(success=True, data=LoginData.model_validate(token_data))
