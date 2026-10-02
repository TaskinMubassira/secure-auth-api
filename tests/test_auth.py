import jwt
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import create_app

GOOD = "Correct-Horse-42"


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(str(tmp_path / "test.db")))


def register(client, email="tasmia@example.com", password=GOOD):
    return client.post("/auth/register", json={"email": email, "password": password})


def login(client, email="tasmia@example.com", password=GOOD):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_register_and_login_and_read_profile(client):
    assert register(client).status_code == 201
    token = login(client).json()["access_token"]
    me = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["email"] == "tasmia@example.com"
    assert "password_hash" not in me.json()


@pytest.mark.parametrize("password", ["short1A", "alllowercase123", "NoNumbersHereAtAll", "tasmiaTasmia123"])
def test_weak_passwords_are_rejected(client, password):
    assert register(client, password=password).status_code == 422


def test_duplicate_email_is_rejected_case_insensitively(client):
    register(client)
    assert register(client, email="TASMIA@example.com").status_code == 409


def test_wrong_password_and_unknown_user_get_the_same_message(client):
    register(client)
    wrong = login(client, password="Wrong-Horse-42")
    unknown = login(client, email="nobody@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_passwords_are_stored_hashed(client, tmp_path):
    register(client)
    import sqlite3

    stored = sqlite3.connect(tmp_path / "test.db").execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored.startswith("$2b$") and GOOD not in stored


def test_account_locks_after_repeated_failures(tmp_path):
    client = TestClient(create_app(str(tmp_path / "lock.db"), login_attempts_per_minute=100))
    register(client)
    for _ in range(settings.max_failed_logins):
        assert login(client, password="Wrong-Horse-42").status_code == 401
    # Locked now, even with the right password.
    assert login(client).status_code == 423


def test_login_is_rate_limited(client):
    register(client)
    codes = [login(client, password="Wrong-Horse-42").status_code for _ in range(settings.login_attempts_per_minute + 1)]
    assert codes[-1] == 429


@pytest.mark.parametrize("header", [None, "Bearer not-a-token"])
def test_profile_requires_a_valid_token(client, header):
    headers = {"Authorization": header} if header else {}
    assert client.get("/users/me", headers=headers).status_code == 401


def test_tampered_token_is_rejected(client):
    register(client)
    forged = jwt.encode({"sub": "1", "exp": 9999999999, "type": "access"}, "attacker-secret-that-is-long-enough-for-hs256", algorithm="HS256")
    assert client.get("/users/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_security_headers_are_set(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
