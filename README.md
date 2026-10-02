# 🛡️ Secure Auth API

[![tests](https://github.com/TaskinMubassira/secure-auth-api/actions/workflows/tests.yml/badge.svg)](https://github.com/TaskinMubassira/secure-auth-api/actions/workflows/tests.yml)

A small but carefully built **authentication API** in Python (FastAPI). It shows how to do sign-up and login the safe way:
hashed passwords, short-lived JWT tokens, rate limiting, account lockout and protection against user enumeration.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/register` | Create an account (`email`, `password`) |
| `POST` | `/auth/login` | Get an access token |
| `GET` | `/users/me` | Current user — needs `Authorization: Bearer <token>` |
| `GET` | `/health` | Health check |

Interactive docs are available at `/docs` when the server is running.

## Security features

| Threat | How this API handles it | OWASP Top 10 |
|---|---|---|
| Stolen database | Passwords hashed with **bcrypt** (cost 12, unique salt per user); hashes are never returned | A02 Cryptographic Failures |
| Weak passwords | At least 12 characters, upper- and lower-case and a number, must not contain the email name | A07 Identification & Authentication Failures |
| Password guessing / brute force | **Rate limit** of 5 login attempts per minute per IP (`429` + `Retry-After`) and **account lockout** after 5 failed logins (`423`) | A07 |
| Account discovery (user enumeration) | Same error for “no such user” and “wrong password”, and the same bcrypt work in both cases (equal timing) | A07 |
| Forged or stolen tokens | Signed **HS256 JWT** with a secret from the environment, 15-minute expiry, `exp`/`sub`/`type` claims checked | A02 / A07 |
| SQL injection | Every query uses **parameters**, never string formatting | A03 Injection |
| Clickjacking, MIME sniffing, caching of tokens | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer` | A05 Security Misconfiguration |
| Bad input | Request bodies validated with **Pydantic** (`EmailStr`, length limits) | A03 |

## Getting started

```bash
git clone https://github.com/TaskinMubassira/secure-auth-api.git
cd secure-auth-api
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt

copy .env.example .env          # macOS/Linux: cp .env.example .env  — then set SECRET_KEY
uvicorn app.main:app --reload --env-file .env   # http://127.0.0.1:8000/docs
pytest                          # run the tests
```

### Try it

```bash
curl -X POST http://127.0.0.1:8000/auth/register -H "Content-Type: application/json" \
     -d '{"email": "tasmia@example.com", "password": "Correct-Horse-42"}'

curl -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" \
     -d '{"email": "tasmia@example.com", "password": "Correct-Horse-42"}'
# → {"access_token": "eyJ...", "token_type": "bearer", "expires_in": 900}

curl http://127.0.0.1:8000/users/me -H "Authorization: Bearer eyJ..."
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | random per start | Key that signs tokens — **set a long random value in production** |
| `DATABASE_PATH` | `auth.db` | SQLite database file |
| `ACCESS_TOKEN_MINUTES` | `15` | Token lifetime |
| `LOGIN_ATTEMPTS_PER_MINUTE` | `5` | Rate limit per IP |
| `MAX_FAILED_LOGINS` / `LOCKOUT_MINUTES` | `5` / `15` | Account lockout |
| `BCRYPT_ROUNDS` | `12` | bcrypt cost |

## Project structure

```text
app/
├── main.py        # routes, auth dependency, security headers
├── security.py    # bcrypt hashing, password policy, JWT
├── ratelimit.py   # sliding-window rate limiter
├── db.py          # SQLite with parameterised queries
└── config.py      # settings from environment variables
tests/             # 14 pytest tests covering the security features
```

## Possible next steps

Refresh tokens with rotation, email verification, two-factor authentication (TOTP), and a shared Redis rate limiter for multiple servers.

## License

MIT © Tasmia Taskin Mubassira
