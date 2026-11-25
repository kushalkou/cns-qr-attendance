"""Configuration + key management.

Key hierarchy (explain this in the viva):

    MASTER_KEY (32 random bytes, lives only in .env, never in git or the DB)
      ├── HKDF(info="qr-token|<session_id>")  -> per-session HMAC key for rotating QR tokens
      └── HKDF(info="report-key-wrap")        -> key that encrypts the Ed25519 private key on disk

    Ed25519 signing key  (keys/report_signing_key.pem, encrypted at rest)
      └── public half     (keys/report_signing_pub.pem, safe to publish)
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
KEYS_DIR = ROOT / "keys"
DATA_DIR = ROOT / "data"


def _load_env_file() -> None:
    """Tiny .env loader so we don't need python-dotenv."""
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def ensure_env() -> None:
    """Create .env with a fresh master key on first run."""
    if ENV_FILE.exists():
        return
    ENV_FILE.write_text(
        "# Generated on first run. NEVER commit this file.\n"
        f"MASTER_KEY={secrets.token_hex(32)}\n"
        "# QR rotation period in seconds\n"
        "QR_PERIOD=10\n"
        "# Comma-separated CIDRs students must scan from (empty = disabled), e.g. 192.168.1.0/24\n"
        "ALLOWED_SUBNETS=\n"
        "# Minimum attendance percentage before a student is a defaulter\n"
        "DEFAULTER_THRESHOLD=75\n"
    )
    os.chmod(ENV_FILE, 0o600)


ensure_env()
_load_env_file()

MASTER_KEY: bytes = bytes.fromhex(os.environ["MASTER_KEY"])
if len(MASTER_KEY) != 32:
    raise RuntimeError("MASTER_KEY must be 32 bytes (64 hex chars)")

QR_PERIOD = int(os.environ.get("QR_PERIOD", "10"))
ALLOWED_SUBNETS = [s.strip() for s in os.environ.get("ALLOWED_SUBNETS", "").split(",") if s.strip()]
DEFAULTER_THRESHOLD = float(os.environ.get("DEFAULTER_THRESHOLD", "75"))
DB_PATH = Path(os.environ.get("DB_PATH", str(DATA_DIR / "attendance.db")))

SESSION_TTL_SECONDS = 2 * 60 * 60      # login sessions expire after 2 hours
DEVICE_SIG_MAX_SKEW = 60               # phone clock may differ from server by this much
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 5 * 60
COOKIE_NAME = "qa_session"

KEYS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)
