"""Secure authentication API: register, log in, and read the current user with a JWT."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

from .config import settings
from .db import Database
from .ratelimit import RateLimiter
from .security import DUMMY_HASH, create_access_token, decode_access_token, hash_password, password_problems, verify_password


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    id: int
    email: EmailStr
    created_at: str


def create_app(database_path: str | None = None, login_attempts_per_minute: int | None = None) -> FastAPI:
    app = FastAPI(title="Secure Auth API", version="1.0.0")
    db = Database(database_path or settings.database_path)
    login_limiter = RateLimiter(login_attempts_per_minute or settings.login_attempts_per_minute)
    bearer = HTTPBearer(auto_error=False)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
        unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token", {"WWW-Authenticate": "Bearer"})
        if creds is None:
            raise unauthorized
        try:
            user = db.find_by_id(decode_access_token(creds.credentials))
        except (jwt.PyJWTError, ValueError):
            raise unauthorized from None
        if user is None:
            raise unauthorized
        return user

    @app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
    def register(body: Credentials):
        problems = password_problems(body.password, body.email)
        if problems:
            raise HTTPException(422, {"password": problems})
        if db.find_by_email(body.email):
            raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
        user_id = db.create_user(body.email, hash_password(body.password))
        return dict(db.find_by_id(user_id))

    @app.post("/auth/login", response_model=TokenOut)
    def login(body: Credentials, request: Request):
        client = request.client.host if request.client else "unknown"
        if not login_limiter.allow(client):
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many login attempts. Try again later.",
                {"Retry-After": str(login_limiter.retry_after(client))},
            )

        # Same message for "no such user" and "wrong password", so attackers cannot discover accounts.
        invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
        user = db.find_by_email(body.email)
        if user is None:
            verify_password(body.password, DUMMY_HASH)  # equal timing
            raise invalid

        now = datetime.now(timezone.utc)
        if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > now:
            raise HTTPException(status.HTTP_423_LOCKED, "Account temporarily locked after repeated failed logins")

        if not verify_password(body.password, user["password_hash"]):
            locks = user["failed_logins"] + 1 >= settings.max_failed_logins
            db.record_failed_login(user["id"], (now + timedelta(minutes=settings.lockout_minutes)).isoformat() if locks else None)
            raise invalid

        db.reset_failed_logins(user["id"])
        return TokenOut(access_token=create_access_token(user["id"]), expires_in=settings.access_token_minutes * 60)

    @app.get("/users/me", response_model=UserOut)
    def me(user=Depends(current_user)):
        return dict(user)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
