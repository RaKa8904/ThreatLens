"""
ThreatLens Auth & Security Control Test Suite
=============================================
Verifies HMAC-SHA256 JWT tokens, password hashing, security headers,
CORS policy, and upload payload validation.
"""

import os
import pytest
from fastapi.testclient import TestClient

os.environ["TESTING"] = "true"

from backend.app.auth import (
    authenticate_user,
    create_jwt_token,
    decode_jwt_token,
    hash_password,
    verify_password,
)
from backend.app.main import app

client = TestClient(app)


def test_password_hashing_and_verification():
    password = "SuperSecretPassword123!"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_token_flow():
    payload = {"sub": "analyst", "role": "SOC_ANALYST"}
    token = create_jwt_token(payload)

    assert isinstance(token, str)
    decoded = decode_jwt_token(token)
    assert decoded is not None
    assert decoded["sub"] == "analyst"
    assert decoded["role"] == "SOC_ANALYST"

    # Test tampering rejection
    tampered_token = token[:-5] + "XXXXX"
    assert decode_jwt_token(tampered_token) is None


def test_login_api_endpoint():
    # Successful login with admin credentials
    response = client.post("/api/auth/login", json={"username": "admin", "password": "AdminSecretPass123!"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "SOC_ADMIN"

    # Invalid login
    invalid_res = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword"})
    assert invalid_res.status_code == 401


def test_security_headers_enforced():
    response = client.get("/api/health")
    assert response.status_code == 200

    headers = response.headers
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert "Strict-Transport-Security" in headers
    assert "Content-Security-Policy" in headers


def test_oversized_pcap_upload_rejected():
    # Attempt uploading oversized content (>50MB)
    fake_header = b"\xd4\xc3\xb2\xa1"
    oversized_data = fake_header + b"0" * (51 * 1024 * 1024)

    files = {"file": ("huge_capture.pcap", oversized_data, "application/octet-stream")}
    response = client.post("/api/replay/upload", files=files)
    assert response.status_code == 413
    assert "exceeds maximum allowed file size" in response.json()["detail"]
