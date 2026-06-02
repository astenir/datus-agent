"""JWT-backed RBAC auth provider for API deployments."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterable, List, Optional

import jwt
from fastapi import HTTPException, Request, status

from datus.api.auth.context import AppContext
from datus.api.auth.provider import EvictCallback
from datus.configuration.agent_config import AgentConfig, DbConfig
from datus.configuration.agent_config_loader import load_agent_config
from datus.tools.db_tools.restricted_connector import _normalize_allowed_tables

_ALLOWLIST_FIELDS = ("allowed_databases", "allowed_schemas", "allowed_tables")
_DEFAULT_JWT = {"secret_key": "change-me", "algorithm": "HS256", "expiration_hours": 8}
_DENY_ALL_TOKEN = "__datus_no_allowed_objects__"


class RbacAuthProvider:
    """Authenticate users with JWT and apply role datasource allowlists.

    Configuration shape under ``agent.api.auth_provider.kwargs``:

    ```yaml
    jwt:
      secret_key: ${DATUS_RBAC_JWT_SECRET}
      expiration_hours: 8
    users:
      alice:
        password_hash: pbkdf2_sha256$...
        roles: [analyst]
    roles:
      analyst:
        datasources:
          finance:
            allowed_schemas: [mart]
            allowed_tables: [mart.orders]
    ```
    """

    def __init__(
        self,
        *,
        jwt: Optional[Dict[str, Any]] = None,
        users: Optional[Dict[str, Any]] = None,
        roles: Optional[Dict[str, Any]] = None,
        datasource: str = "default",
    ):
        jwt_config = {**_DEFAULT_JWT, **(jwt or {})}
        self.jwt_secret = os.getenv("DATUS_RBAC_JWT_SECRET", str(jwt_config.get("secret_key") or ""))
        self.jwt_algorithm = str(jwt_config.get("algorithm") or "HS256")
        self.jwt_expiration_hours = float(jwt_config.get("expiration_hours") or 8)
        self.users = users or {}
        self.roles = roles or {}
        self.datasource = datasource
        self._evict_callbacks: list[EvictCallback] = []

    @staticmethod
    def hash_password(password: str, *, iterations: int = 260000, salt: Optional[bytes] = None) -> str:
        """Return a PBKDF2-SHA256 password hash suitable for YAML config."""
        salt_bytes = salt or os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
        salt_b64 = base64.urlsafe_b64encode(salt_bytes).decode("ascii").rstrip("=")
        digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return f"pbkdf2_sha256${iterations}${salt_b64}${digest_b64}"

    @staticmethod
    def _decode_b64(value: str) -> bytes:
        padded = value + ("=" * (-len(value) % 4))
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    @classmethod
    def verify_password(cls, password: str, password_hash: str) -> bool:
        """Verify a password against the provider's PBKDF2-SHA256 hash format."""
        try:
            scheme, raw_iterations, salt_b64, digest_b64 = str(password_hash).split("$", 3)
            if scheme != "pbkdf2_sha256":
                return False
            iterations = int(raw_iterations)
            salt = cls._decode_b64(salt_b64)
            expected = cls._decode_b64(digest_b64)
        except Exception:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual, expected)

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """Validate credentials and issue a bearer token."""
        user = self.users.get(username)
        if not isinstance(user, dict) or not self._user_password_matches(user, password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

        roles = [str(role) for role in user.get("roles") or [] if str(role).strip()]
        expires_at = datetime.now(timezone.utc) + timedelta(hours=self.jwt_expiration_hours)
        payload = {
            "sub": username,
            "roles": roles,
            "exp": expires_at,
            "iat": datetime.now(timezone.utc),
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": int(self.jwt_expiration_hours * 3600),
            "user_id": username,
            "roles": roles,
        }

    def _user_password_matches(self, user: Dict[str, Any], password: str) -> bool:
        password_hash = user.get("password_hash")
        if password_hash and self.verify_password(password, str(password_hash)):
            return True
        password_env = user.get("password_env")
        if password_env:
            expected = os.getenv(str(password_env), "")
            return bool(expected) and hmac.compare_digest(password, expected)
        return False

    async def authenticate(self, request: Request) -> AppContext:
        """Authenticate a bearer JWT and return an RBAC-scoped AppContext."""
        payload = self._decode_token_from_request(request)
        user_id = str(payload.get("sub") or "")
        if not user_id or user_id not in self.users:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
        roles = [str(role) for role in payload.get("roles") or [] if str(role).strip()]
        base_config = load_agent_config(datasource=self.datasource)
        scoped_config = self._scoped_config_for_roles(base_config, roles)
        return AppContext(user_id=user_id, project_id=f"rbac:{user_id}", config=scoped_config)

    def _decode_token_from_request(self, request: Request) -> Dict[str, Any]:
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
        try:
            return jwt.decode(token.strip(), self.jwt_secret, algorithms=[self.jwt_algorithm])
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired") from exc
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    def _scoped_config_for_roles(self, base_config: AgentConfig, roles: List[str]) -> AgentConfig:
        grants = self._datasource_grants_for_roles(roles)
        if not grants:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User has no datasource grants")

        config = copy.deepcopy(base_config)
        scoped_datasources: Dict[str, DbConfig] = {}
        for datasource_name, grant in grants.items():
            base_db = config.services.datasources.get(datasource_name)
            if base_db is None:
                continue
            scoped_datasources[datasource_name] = self._apply_grant_to_db_config(base_db, grant)

        if not scoped_datasources:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="User has no configured datasource grants"
            )

        config.services.datasources = scoped_datasources
        if config.current_datasource not in scoped_datasources:
            config.current_datasource = next(iter(scoped_datasources))
        return config

    def _datasource_grants_for_roles(self, role_names: Iterable[str]) -> Dict[str, Dict[str, Optional[List[str]]]]:
        grants: Dict[str, Dict[str, Optional[List[str]]]] = {}
        for role_name in role_names:
            role = self.roles.get(role_name)
            if not isinstance(role, dict):
                continue
            datasources = role.get("datasources") or {}
            if not isinstance(datasources, dict):
                continue
            for datasource_name, raw_grant in datasources.items():
                grant = raw_grant if isinstance(raw_grant, dict) else {}
                merged = grants.setdefault(str(datasource_name), {field: [] for field in _ALLOWLIST_FIELDS})
                for field in _ALLOWLIST_FIELDS:
                    if field not in grant or grant.get(field) in (None, ""):
                        merged[field] = None
                    elif merged[field] is not None:
                        merged[field] = _merge_unique(merged[field] or [], _normalize_allowed_tables(grant.get(field)))
        return grants

    def _apply_grant_to_db_config(self, db_config: DbConfig, grant: Dict[str, Optional[List[str]]]) -> DbConfig:
        updated = copy.deepcopy(db_config)
        extra = dict(updated.extra or {})
        for field in _ALLOWLIST_FIELDS:
            role_values = grant.get(field)
            base_values = _normalize_allowed_tables(extra.get(field))
            if role_values is None:
                if base_values:
                    extra[field] = base_values
                else:
                    extra.pop(field, None)
                continue
            role_values = _normalize_allowed_tables(role_values)
            scoped_values = _intersect_with_base(role_values, base_values) if base_values else role_values
            extra[field] = scoped_values or [_DENY_ALL_TOKEN]
        updated.extra = extra or None
        return updated

    def on_evict(self, callback: EvictCallback) -> None:
        self._evict_callbacks.append(callback)


def _merge_unique(left: List[str], right: List[str]) -> List[str]:
    result = list(left)
    seen = set(result)
    for item in right:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _intersect_with_base(role_values: List[str], base_values: List[str]) -> List[str]:
    """Keep role values that do not exceed an existing datasource allowlist."""
    allowed: List[str] = []
    for role_value in role_values:
        normalized_role = role_value.lower()
        for base_value in base_values:
            normalized_base = str(base_value).lower()
            if fnmatchcase(normalized_role, normalized_base.replace("%", "*")) or fnmatchcase(
                normalized_base, normalized_role.replace("%", "*")
            ):
                allowed.append(role_value)
                break
    return allowed
