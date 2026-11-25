"""Authentication (Argon2id + server-side sessions) and role-based access control."""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request

from . import config
from .db import get_db, log_event

_ph = PasswordHasher()  # Argon2id, salted, memory-hard: slow for attackers, fine for one login


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def check_password(pw_hash: str, pw: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except (VerificationError, InvalidHashError):
        return False


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def login(username: str, password: str, ip: str) -> tuple[str | None, str]:
    """Returns (session_token, error). Locks the account after repeated failures."""
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        now = time.time()
        if user and user["locked_until"] > now:
            log_event(db, "login_locked", username, user_id=user["id"], ip=ip)
            return None, f"Account locked. Try again in {int(user['locked_until'] - now)}s."
        if not user or not check_password(user["pw_hash"], password):
            if user:
                fails = user["failed_logins"] + 1
                locked = now + config.LOGIN_LOCK_SECONDS if fails >= config.LOGIN_MAX_FAILS else 0
                db.execute(
                    "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                    (0 if locked else fails, locked, user["id"]),
                )
            log_event(db, "login_failed", username, user_id=user["id"] if user else None, ip=ip)
            return None, "Invalid username or password."  # same message either way: no user enumeration
        db.execute("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (user["id"],))
        token = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?,?,?)",
            (_sha256(token), user["id"], now + config.SESSION_TTL_SECONDS),
        )
        log_event(db, "login_ok", username, user_id=user["id"], ip=ip)
        return token, ""


def logout(token: str | None) -> None:
    if token:
        with get_db() as db:
            db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (_sha256(token),))


def current_user(request: Request):
    token = request.cookies.get(config.COOKIE_NAME)
    if not token:
        return None
    with get_db() as db:
        row = db.execute(
            "SELECT u.* FROM auth_sessions s JOIN users u ON u.id = s.user_id"
            " WHERE s.token_hash = ? AND s.expires_at > ?",
            (_sha256(token), time.time()),
        ).fetchone()
    return dict(row) if row else None


def require(*roles: str):
    """FastAPI dependency: `user = Depends(require('faculty'))`."""

    def dep(request: Request):
        user = current_user(request)
        if not user:
            raise HTTPException(401, "Not logged in")
        if roles and user["role"] not in roles:
            with get_db() as db:
                log_event(db, "rbac_denied", f"{user['role']} -> {request.url.path}",
                          user_id=user["id"], ip=client_ip(request))
            raise HTTPException(403, "Your role cannot do this")
        return user

    return dep


def ip_allowed(ip: str) -> bool:
    """Optional classroom-network check (ALLOWED_SUBNETS in .env)."""
    if not config.ALLOWED_SUBNETS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in config.ALLOWED_SUBNETS)
