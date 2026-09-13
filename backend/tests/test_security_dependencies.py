"""Exercise Centaur auth and framework form parsing with no external services."""

import base64
import hashlib
import hmac
import io
import json
import secrets
import time
import uuid
from types import SimpleNamespace
from typing import Annotated
from unittest.mock import AsyncMock, Mock

import jwt
import pytest
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.testclient import TestClient
from python_multipart import parse_form


@pytest.fixture
def auth_client(monkeypatch):
    from backend.api.auth import router as auth
    from backend.api.database import get_db
    from backend.api.main import app

    monkeypatch.setattr(auth.settings, "jwt_secret", secrets.token_hex(32))
    monkeypatch.setattr(auth.settings, "jwt_algorithm", "HS256")
    user = SimpleNamespace(
        id=uuid.uuid4(),
        username="fixture-user",
        display_name="Fixture",
        avatar_url=None,
        bio=None,
    )
    result = Mock()
    result.scalar_one_or_none.return_value = user
    db = AsyncMock()
    db.execute.return_value = result

    async def database():
        yield db

    original = dict(app.dependency_overrides)
    app.dependency_overrides[get_db] = database
    try:
        with TestClient(app) as client:
            yield client, auth, user, db
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original)


def _session(client, token):
    client.cookies.set("session", token)
    return client.get("/api/auth/me")


def test_session_roundtrip_through_actual_auth_endpoint(auth_client):
    client, auth, user, db = auth_client
    token = auth.create_jwt(user.id)
    payload = auth.decode_jwt(token)
    assert payload["sub"] == str(user.id)
    assert payload["exp"] > payload["iat"]
    response = _session(client, token)
    assert response.status_code == 200
    assert response.json()["id"] == str(user.id)
    assert response.json()["username"] == user.username
    db.execute.assert_awaited_once()


@pytest.mark.parametrize(
    "case",
    [
        "expired",
        "wrong-key",
        "wrong-algorithm",
        "malformed",
        "invalid-subject",
        "missing-subject",
    ],
)
def test_invalid_session_fails_before_database_lookup(auth_client, case):
    client, auth, user, db = auth_client
    payload = {"sub": str(user.id), "exp": int(time.time()) + 60}
    key, algorithm = auth.settings.jwt_secret, "HS256"
    if case == "expired":
        payload["exp"] = int(time.time()) - 60
    elif case == "wrong-key":
        key = secrets.token_hex(32)
    elif case == "wrong-algorithm":
        algorithm = "HS384"
    elif case == "invalid-subject":
        payload["sub"] = "not-a-uuid"
    elif case == "missing-subject":
        del payload["sub"]
    token = (
        "not-a-token"
        if case == "malformed"
        else jwt.encode(payload, key, algorithm=algorithm)
    )
    response = _session(client, token)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid session"}
    db.execute.assert_not_awaited()


def test_unknown_critical_header_rejected_at_auth_boundary(auth_client):
    client, auth, user, db = auth_client

    # Construct a correctly signed token ourselves: PyJWT's updated encoder may
    # reject the critical extension before the decoder sees the test input.
    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    header = segment({"alg": "HS256", "crit": ["unrecognized"], "unrecognized": True})
    payload = segment({"sub": str(user.id), "exp": int(time.time()) + 60})
    signing_input = header + b"." + payload
    signature = hmac.new(
        auth.settings.jwt_secret.encode(), signing_input, hashlib.sha256
    ).digest()
    token = (
        signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")
    ).decode()
    assert _session(client, token).status_code == 401
    db.execute.assert_not_awaited()


def test_explicit_invalid_bearer_does_not_fall_back_to_valid_cookie(auth_client):
    client, auth, user, db = auth_client
    client.cookies.set("session", auth.create_jwt(user.id))
    response = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired API token"}
    db.execute.assert_not_awaited()


def test_logout_clears_session_cookie(auth_client):
    client, auth, user, _ = auth_client
    client.cookies.set("session", auth.create_jwt(user.id))
    response = client.post("/api/auth/logout")
    assert response.status_code == 204
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_empty_signing_key_is_rejected(auth_client, monkeypatch):
    _, auth, user, _ = auth_client
    monkeypatch.setattr(auth.settings, "jwt_secret", "")
    with pytest.raises(jwt.InvalidKeyError):
        auth.create_jwt(user.id)


@pytest.fixture
def form_client():
    # Centaur currently has no upload/form endpoint. This isolated harness proves
    # compatibility of its pinned FastAPI/Starlette stack with python-multipart.
    app = FastAPI()

    @app.post("/upload")
    async def upload(
        label: Annotated[str, Form()], file: Annotated[UploadFile, File()]
    ):
        return {
            "label": label,
            "name": file.filename,
            "body": (await file.read()).decode(),
        }

    @app.post("/form")
    async def form(value: Annotated[str, Form()]):
        return {"value": value}

    with TestClient(app) as client:
        yield client


def test_framework_multipart_upload_preserves_content_and_filename(form_client):
    response = form_client.post(
        "/upload",
        data={"label": "sample"},
        files={"file": ("sample.txt", b"payload", "text/plain")},
    )
    assert response.status_code == 200
    assert response.json() == {
        "label": "sample",
        "name": "sample.txt",
        "body": "payload",
    }


def test_urlencoded_semicolon_is_data_not_a_second_field(form_client):
    response = form_client.post(
        "/form",
        content="value=first;injected=second",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    assert response.json() == {"value": "first;injected=second"}


def test_multipart_missing_boundary_returns_client_error(form_client):
    response = form_client.post(
        "/upload", content=b"invalid", headers={"Content-Type": "multipart/form-data"}
    )
    assert response.status_code == 400


def test_negative_content_length_rejected_before_reading_body():
    body = io.BytesIO(b"value=payload")
    with pytest.raises(ValueError):
        parse_form(
            {
                "Content-Type": b"application/x-www-form-urlencoded",
                "Content-Length": b"-1",
            },
            body,
            lambda field: None,
            lambda file: None,
        )
    assert body.tell() == 0


def test_oauth_callback_issues_verifiable_secure_session(auth_client, monkeypatch):
    client, auth, user, db = auth_client
    upstream = AsyncMock()
    upstream.post.return_value = Mock(
        json=lambda: {"access_token": "fixture-oauth-token"}
    )
    upstream.get.return_value = Mock(json=lambda: {"id": 123, "login": user.username})
    context = AsyncMock()
    context.__aenter__.return_value = upstream
    monkeypatch.setattr(auth.httpx, "AsyncClient", Mock(return_value=context))
    response = client.get(
        "/api/auth/callback", params={"code": "fixture-code"}, follow_redirects=False
    )
    assert response.status_code == 307
    assert response.headers["location"] == auth.settings.frontend_url + "/dashboard"
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    token = response.cookies["session"]
    assert auth.decode_jwt(token)["sub"] == str(user.id)
    db.commit.assert_awaited_once()
    upstream.post.assert_awaited_once()
    upstream.get.assert_awaited_once()


def test_api_health_and_openapi_routes_remain_available(auth_client):
    client, _, _, db = auth_client
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    schema = client.get("/openapi.json")
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    assert "get" in paths["/api/auth/me"]
    assert "post" in paths["/api/auth/tokens"]
    assert "delete" in paths["/api/auth/tokens/{token_id}"]
    db.execute.assert_not_awaited()
