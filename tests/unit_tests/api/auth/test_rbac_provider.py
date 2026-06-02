"""Unit tests for datus.api.auth.rbac_provider."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from datus.api.constants import HEADER_USER_ID


def _request_with_bearer(token: str) -> MagicMock:
    request = MagicMock()
    request.headers = {"Authorization": f"Bearer {token}"}
    return request


@pytest.mark.asyncio
class TestRbacAuthProvider:
    async def test_login_token_authenticates_and_scopes_config(self, real_agent_config):
        """A logged-in user receives an AgentConfig restricted by role datasource grants."""
        from datus.api.auth.rbac_provider import RbacAuthProvider

        provider = RbacAuthProvider(
            jwt={"secret_key": "test-secret-with-at-least-32-bytes", "expiration_hours": 1},
            users={
                "alice": {
                    "password_hash": RbacAuthProvider.hash_password("correct horse"),
                    "roles": ["analyst"],
                }
            },
            roles={
                "analyst": {
                    "datasources": {
                        "california_schools": {
                            "allowed_tables": ["schools"],
                            "allowed_schemas": ["main"],
                        }
                    }
                }
            },
            datasource="california_schools",
        )

        with patch("datus.api.auth.rbac_provider.load_agent_config", return_value=real_agent_config):
            token = provider.login("alice", "correct horse")["access_token"]
            ctx = await provider.authenticate(_request_with_bearer(token))

        assert ctx.user_id == "alice"
        assert ctx.project_id == "rbac:alice"
        assert ctx.config is not real_agent_config
        assert set(ctx.config.datasource_configs) == {"california_schools"}
        scoped_db = ctx.config.datasource_configs["california_schools"]["california_schools"]
        assert scoped_db.extra["allowed_tables"] == ["schools"]
        assert scoped_db.extra["allowed_schemas"] == ["main"]

    async def test_login_rejects_invalid_password(self):
        """Invalid credentials fail before any token is issued."""
        from datus.api.auth.rbac_provider import RbacAuthProvider

        provider = RbacAuthProvider(
            jwt={"secret_key": "test-secret-with-at-least-32-bytes"},
            users={"alice": {"password_hash": RbacAuthProvider.hash_password("pw"), "roles": ["analyst"]}},
            roles={"analyst": {"datasources": {"ds": {}}}},
        )

        with pytest.raises(HTTPException) as exc:
            provider.login("alice", "wrong")

        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_authenticate_requires_bearer_token(self):
        """RBAC mode is fail-closed when Authorization is missing."""
        from datus.api.auth.rbac_provider import RbacAuthProvider

        provider = RbacAuthProvider(jwt={"secret_key": "test-secret-with-at-least-32-bytes"}, users={}, roles={})
        request = MagicMock()
        request.headers = {HEADER_USER_ID: "alice"}

        with pytest.raises(HTTPException) as exc:
            await provider.authenticate(request)

        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_authenticate_rejects_role_without_datasource_grant(self, real_agent_config):
        """A valid user with no datasource grants cannot obtain a usable project config."""
        from datus.api.auth.rbac_provider import RbacAuthProvider

        provider = RbacAuthProvider(
            jwt={"secret_key": "test-secret-with-at-least-32-bytes"},
            users={"alice": {"password_hash": RbacAuthProvider.hash_password("pw"), "roles": ["empty"]}},
            roles={"empty": {"datasources": {}}},
            datasource="california_schools",
        )
        token = provider.login("alice", "pw")["access_token"]

        with (
            patch("datus.api.auth.rbac_provider.load_agent_config", return_value=real_agent_config),
            pytest.raises(HTTPException) as exc,
        ):
            await provider.authenticate(_request_with_bearer(token))

        assert exc.value.status_code == 403

    async def test_role_allowlist_intersection_empty_is_fail_closed(self, real_agent_config):
        """Role grants broader than an existing datasource allowlist must not become unrestricted."""
        from datus.api.auth.rbac_provider import RbacAuthProvider

        base_db = real_agent_config.services.datasources["california_schools"]
        base_db.extra = {**(base_db.extra or {}), "allowed_tables": ["schools"]}
        provider = RbacAuthProvider(
            jwt={"secret_key": "test-secret-with-at-least-32-bytes"},
            users={"alice": {"password_hash": RbacAuthProvider.hash_password("pw"), "roles": ["analyst"]}},
            roles={"analyst": {"datasources": {"california_schools": {"allowed_tables": ["districts"]}}}},
            datasource="california_schools",
        )
        token = provider.login("alice", "pw")["access_token"]

        with patch("datus.api.auth.rbac_provider.load_agent_config", return_value=real_agent_config):
            ctx = await provider.authenticate(_request_with_bearer(token))

        scoped_db = ctx.config.datasource_configs["california_schools"]["california_schools"]
        assert scoped_db.extra["allowed_tables"] == ["__datus_no_allowed_objects__"]
