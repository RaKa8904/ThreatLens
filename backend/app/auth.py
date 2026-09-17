"""
ThreatLens Authentication & RBAC Security Module
=================================================
Provides HMAC-SHA256 JWT token generation, PBKDF2 password hashing,
user credential authentication, and Role-Based Access Control (RBAC).
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import secrets
from typing import Any, Dict, Optional, List

from fastapi import Depends, HTTPException, Header, Query, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# Configuration from Environment
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "threatlens_super_secret_soc_jwt_key_2026_change_in_prod")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "480"))
DISABLE_AUTH_DEV = os.getenv("DISABLE_AUTH_FOR_DEV", "false").lower() in ("true", "1", "yes")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


class User(BaseModel):
    username: str
    role: str  # "SOC_ADMIN" | "SOC_ANALYST"
    disabled: bool = False


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: User


class LoginRequest(BaseModel):
    username: str
    password: str


# Password Hashing Helpers (NIST-compliant PBKDF2-HMAC-SHA256)
def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return base64.b64encode(salt + key).decode("ascii")


def verify_password(password: str, hashed_str: str) -> bool:
    try:
        data = base64.b64decode(hashed_str.encode("ascii"))
        salt = data[:16]
        stored_key = data[16:]
        new_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(stored_key, new_key)
    except Exception:
        return False


# Standard User Database (Initial In-Memory Registry with Salted Hashes)
_USERS_DB: Dict[str, Dict[str, Any]] = {
    "admin": {
        "username": "admin",
        "password_hash": hash_password(os.getenv("SOC_ADMIN_PASSWORD", "AdminSecretPass123!")),
        "role": "SOC_ADMIN",
        "disabled": False,
    },
    "analyst": {
        "username": "analyst",
        "password_hash": hash_password(os.getenv("SOC_ANALYST_PASSWORD", "AnalystPass123!")),
        "role": "SOC_ANALYST",
        "disabled": False,
    },
}


# Base64URL Encoding/Decoding Helpers
def _b64encode_url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64decode_url(data_str: str) -> bytes:
    padding = "=" * (4 - (len(data_str) % 4))
    return base64.urlsafe_b64encode(base64.urlsafe_b64decode(data_str + padding))


def create_jwt_token(payload: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    to_encode = payload.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"iat": int(now.timestamp()), "exp": int(expire.timestamp())})

    encoded_header = _b64encode_url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64encode_url(json.dumps(to_encode, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")

    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    encoded_signature = _b64encode_url(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
        expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()

        # Re-encode signature to check digest equality securely
        actual_sig = base64.urlsafe_b64decode(encoded_signature + "=" * (4 - (len(encoded_signature) % 4)))
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_bytes = base64.urlsafe_b64decode(encoded_payload + "=" * (4 - (len(encoded_payload) % 4)))
        payload = json.loads(payload_bytes.decode("utf-8"))

        # Expiry Check
        exp = payload.get("exp")
        if exp and int(datetime.now(timezone.utc).timestamp()) > exp:
            return None

        return payload
    except Exception:
        return None


def authenticate_user(username: str, password: str) -> Optional[User]:
    user_record = _USERS_DB.get(username.lower())
    if not user_record or user_record.get("disabled"):
        return None
    if verify_password(password, user_record["password_hash"]):
        return User(username=user_record["username"], role=user_record["role"], disabled=user_record["disabled"])
    return None


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> Optional[User]:
    if DISABLE_AUTH_DEV and not token:
        return User(username="dev_admin", role="SOC_ADMIN", disabled=False)

    if not token:
        if DISABLE_AUTH_DEV:
            return User(username="dev_admin", role="SOC_ADMIN", disabled=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_jwt_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    role = payload.get("role", "SOC_ANALYST")
    return User(username=username, role=role, disabled=False)


def require_role(allowed_roles: List[str]):
    async def role_checker(current_user: Optional[User] = Depends(get_current_user)) -> User:
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {allowed_roles}",
            )
        return current_user
    return role_checker


async def validate_websocket_token(token: Optional[str] = Query(None)) -> Optional[User]:
    """
    Validates token for WebSocket handshake upgrades.
    If no token is supplied, allows read-only SOC_ANALYST connection so live telemetry feeds stream uninterrupted.
    """
    if not token:
        return User(username="anonymous_analyst", role="SOC_ANALYST", disabled=False)

    payload = decode_jwt_token(token)
    if not payload or "sub" not in payload:
        # Fallback to read-only analyst if token expired or invalid
        return User(username="anonymous_analyst", role="SOC_ANALYST", disabled=False)

    return User(username=payload.get("sub"), role=payload.get("role", "SOC_ANALYST"), disabled=False)
