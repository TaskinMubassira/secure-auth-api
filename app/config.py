"""Settings read from environment variables, with safe defaults for local development."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    # In production SECRET_KEY must be set; a random one is generated for local runs (tokens reset on restart).
    secret_key: str = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)
    database_path: str = os.getenv("DATABASE_PATH", "auth.db")
    access_token_minutes: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "15"))
    login_attempts_per_minute: int = int(os.getenv("LOGIN_ATTEMPTS_PER_MINUTE", "5"))
    max_failed_logins: int = int(os.getenv("MAX_FAILED_LOGINS", "5"))
    lockout_minutes: int = int(os.getenv("LOCKOUT_MINUTES", "15"))
    # 12 rounds is a good production cost; tests lower it to stay fast.
    bcrypt_rounds: int = int(os.getenv("BCRYPT_ROUNDS", "12"))


settings = Settings()
