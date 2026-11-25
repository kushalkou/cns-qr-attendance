"""All cryptography in one file, so it is easy to read and explain.

1. HKDF key derivation           -> derive_key()
2. Rotating HMAC QR tokens       -> mint_qr_token() / verify_qr_token()
3. Device-bound ECDSA signatures -> verify_device_signature()
4. Hash-chained attendance log   -> chain_hash()  (verification lives in db.verify_chain)
5. Ed25519 signed reports        -> sign_report() / verify_report()
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import config

GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------- helpers
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical_json(obj) -> bytes:
    """Deterministic JSON: same data -> same bytes -> same hash/signature."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ---------------------------------------------------------------- 1. HKDF
def derive_key(info: str, length: int = 32) -> bytes:
    """HKDF-SHA256(master_key, info). Different `info` -> independent keys.
    Leaking one derived key reveals nothing about the master or other keys."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info.encode()).derive(
        config.MASTER_KEY
    )


# ---------------------------------------------------------------- 2. QR tokens
def current_window(now: float | None = None) -> int:
    """Time is cut into slots of QR_PERIOD seconds. The QR changes every slot."""
    return int((now if now is not None else time.time()) // config.QR_PERIOD)


def _token_mac(session_id: str, window: int) -> str:
    key = derive_key(f"qr-token|{session_id}")
    mac = hmac.new(key, f"{session_id}.{window}".encode(), hashlib.sha256).digest()
    return b64u(mac[:16])  # 128-bit tag is plenty and keeps the QR small


def mint_qr_token(session_id: str, now: float | None = None) -> str:
    """QR content = <session_id>.<window>.<HMAC tag>"""
    w = current_window(now)
    return f"{session_id}.{w}.{_token_mac(session_id, w)}"


@dataclass
class TokenCheck:
    ok: bool
    reason: str = ""
    session_id: str = ""
    window: int = -1


def verify_qr_token(token: str, now: float | None = None) -> TokenCheck:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return TokenCheck(False, "malformed token")
    session_id, w_str, tag = parts
    try:
        window = int(w_str)
    except ValueError:
        return TokenCheck(False, "malformed token")
    # Integrity + authenticity: only the server (holding the key) can produce a valid tag.
    if not hmac.compare_digest(tag, _token_mac(session_id, window)):  # constant-time compare
        return TokenCheck(False, "forged token (bad HMAC)", session_id, window)
    # Freshness: accept current slot or the one just before (scan may straddle a boundary).
    cw = current_window(now)
    if window > cw:
        return TokenCheck(False, "token from the future", session_id, window)
    if cw - window > 1:
        return TokenCheck(False, "expired token (replay)", session_id, window)
    return TokenCheck(True, "", session_id, window)


# ---------------------------------------------------------------- 3. Device binding
def load_device_pubkey(spki_b64: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_der_public_key(base64.b64decode(spki_b64))
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("device key must be ECDSA P-256")
    return key


def device_fingerprint(spki_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(spki_b64)).hexdigest()[:16]


def scan_message(token: str, user_id: int, ts: int, nonce: str) -> bytes:
    """Exactly what the phone signs. Must match static/js/device.js."""
    return f"{token}|{user_id}|{ts}|{nonce}".encode()


def verify_device_signature(spki_b64: str, message: bytes, sig_b64: str) -> bool:
    """WebCrypto gives raw r||s (64 bytes); `cryptography` wants DER, so convert."""
    try:
        key = load_device_pubkey(spki_b64)
        raw = base64.b64decode(sig_b64)
        if len(raw) != 64:
            return False
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        key.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ---------------------------------------------------------------- 4. Hash chain
def chain_hash(prev_hash: str, record: dict) -> str:
    """hash_i = SHA256(prev_hash || canonical(record_i)).
    Changing any old record changes its hash, which breaks every link after it."""
    return hashlib.sha256(prev_hash.encode() + canonical_json(record)).hexdigest()


# ---------------------------------------------------------------- 5. Ed25519 reports
_PRIV_PATH = config.KEYS_DIR / "report_signing_key.pem"
_PUB_PATH = config.KEYS_DIR / "report_signing_pub.pem"


def _wrap_password() -> bytes:
    return derive_key("report-key-wrap")


def ensure_signing_key() -> None:
    if _PRIV_PATH.exists():
        return
    priv = ed25519.Ed25519PrivateKey.generate()
    _PRIV_PATH.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(_wrap_password()),  # encrypted at rest
        )
    )
    _PRIV_PATH.chmod(0o600)
    _PUB_PATH.write_bytes(
        priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )


def _signing_key() -> ed25519.Ed25519PrivateKey:
    ensure_signing_key()
    return serialization.load_pem_private_key(_PRIV_PATH.read_bytes(), password=_wrap_password())


def public_key_pem() -> str:
    ensure_signing_key()
    return _PUB_PATH.read_text()


def sign_report(report: dict) -> str:
    return base64.b64encode(_signing_key().sign(canonical_json(report))).decode()


def verify_report(report: dict, signature_b64: str, pub_pem: str | None = None) -> bool:
    pub = serialization.load_pem_public_key((pub_pem or public_key_pem()).encode())
    try:
        pub.verify(base64.b64decode(signature_b64), canonical_json(report))
        return True
    except (InvalidSignature, ValueError):
        return False
