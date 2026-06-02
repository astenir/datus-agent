"""Unit tests for datus/api/routes/auth_routes.py."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from datus.api.deps import get_auth_provider
from datus.api.routes.auth_routes import router


class _LoginProvider:
    def login(self, username: str, password: str):
        assert username == "alice"
        assert password == "pw"
        return {
            "access_token": "token-1",
            "token_type": "Bearer",
            "expires_in": 3600,
            "user_id": "alice",
            "roles": ["analyst"],
        }


def test_login_route_returns_token_envelope():
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_auth_provider] = lambda: _LoginProvider()

    with TestClient(app) as client:
        response = client.post("/api/v1/auth/login", json={"username": "alice", "password": "pw"})

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["access_token"] == "token-1"
    assert body["data"]["user_id"] == "alice"
    assert body["data"]["roles"] == ["analyst"]
