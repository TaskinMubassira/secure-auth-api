"""Password hashing, password policy and JWT access tokens."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from .config import settings

ALGORITHM = "HS256"
# A real bcrypt hash, used to spend the same time when the email does not exist (prevents user enumeration).
DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=settings.bcrypt_rounds)).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=settings.bcrypt_rounds)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def password_problems(password: str, email: str = "") -> list[str]:
    """Reasons the password is not acceptable (empty list = OK)."""
    problems = []
    if len(password) < 12:
        problems.append("must be at least 12 characters long")
    if len(password.encode()) > 72:
        problems.append("must be at most 72 bytes (bcrypt limit)")
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and re.search(r"\d", password)):
        problems.append("must contain upper-case, lower-case letters and a number")
    local_part = email.split("@")[0].lower()
    if local_part and len(local_part) >= 3 and local_part in password.lower():
        problems.append("must not contain your email name")
    return problems


def create_access_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "iat": now, "exp": now + timedelta(minutes=settings.access_token_minutes), "type": "access"}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> int:
    """Returns the user id. Raises jwt.PyJWTError when the token is invalid, expired or tampered with."""
    payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM], options={"require": ["exp", "sub"]})
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return int(payload["sub"])
