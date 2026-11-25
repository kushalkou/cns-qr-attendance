"""pytest -q   (runs in-process against a throwaway database)"""
import base64
import os
import secrets
import sqlite3
import tempfile
import time

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

import pytest  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config, crypto_core as cc  # noqa: E402
from scripts import seed  # noqa: E402
from app.main import app  # noqa: E402

seed.main_seed()


# ---------------------------------------------------------------- unit: crypto
def test_token_roundtrip_and_expiry():
    t0 = 1_000_000.0
    tok = cc.mint_qr_token("abcd1234", t0)
    assert cc.verify_qr_token(tok, t0).ok
    assert cc.verify_qr_token(tok, t0 + config.QR_PERIOD).ok          # grace window
    assert not cc.verify_qr_token(tok, t0 + 2 * config.QR_PERIOD).ok  # expired
    assert "future" in cc.verify_qr_token(tok, t0 - config.QR_PERIOD).reason


def test_token_tamper():
    tok = cc.mint_qr_token("abcd1234")
    s, w, tag = tok.split(".")
    assert not cc.verify_qr_token(f"{s}.{int(w) + 1}.{tag}").ok      # changed window
    assert not cc.verify_qr_token(f"zzzz9999.{w}.{tag}").ok            # changed session
    assert not cc.verify_qr_token("garbage").ok


def test_hkdf_keys_independent():
    assert cc.derive_key("qr-token|a") != cc.derive_key("qr-token|b")


def test_report_signature():
    rep = {"a": 1, "present": ["x"]}
    sig = cc.sign_report(rep)
    assert cc.verify_report(rep, sig)
    assert not cc.verify_report({**rep, "present": ["x", "y"]}, sig)


# ---------------------------------------------------------------- end to end
class Phone:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())

    def pub(self):
        return base64.b64encode(self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

    def scan(self, token, uid, nonce=None):
        ts, nonce = int(time.time()), nonce or secrets.token_urlsafe(18)
        r, s = decode_dss_signature(self.key.sign(f"{token}|{uid}|{ts}|{nonce}".encode(), ec.ECDSA(hashes.SHA256())))
        return {"token": token, "ts": ts, "nonce": nonce,
                "sig": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()}


def logged_in(u, p):
    c = TestClient(app)
    assert c.post("/login", data={"username": u, "password": p}, follow_redirects=False).status_code == 303
    return c


@pytest.fixture(scope="module")
def world():
    fac = logged_in("prof.rao", "Faculty@123")
    cid = next(c["id"] for c in fac.get("/api/faculty/overview").json()["courses"] if c["code"] == "CNS")
    sid = fac.post("/api/sessions", json={"course_id": cid}).json()["session_id"]
    alice, bob = logged_in("DEMOALICE", "Student@123"), logged_in("DEMOBOB", "Student@123")
    pa, pb = Phone(), Phone()
    assert alice.post("/api/device/register", json={"pubkey": pa.pub()}).status_code == 200
    assert bob.post("/api/device/register", json={"pubkey": pb.pub()}).status_code == 200
    return dict(fac=fac, sid=sid, alice=alice, bob=bob, pa=pa, pb=pb,
                aid=alice.get("/api/me").json()["id"], bid=bob.get("/api/me").json()["id"],
                token=lambda: fac.get(f"/api/sessions/{sid}/live").json()["token"])


def test_full_flow(world):
    w = world
    req = w["pa"].scan(w["token"](), w["aid"])
    assert w["alice"].post("/api/scan", json=req).status_code == 200
    assert w["alice"].post("/api/scan", json=req).status_code == 400                          # nonce replay
    assert w["alice"].post("/api/scan", json=w["pa"].scan(w["token"](), w["aid"])).status_code == 409  # double
    assert w["bob"].post("/api/scan", json=w["pa"].scan(w["token"](), w["bid"])).status_code == 403    # proxy device
    assert w["bob"].post("/api/device/register", json={"pubkey": w["pa"].pub()}).status_code == 409    # rebind
    assert w["bob"].post(f"/api/sessions/{w['sid']}/close").status_code == 403                         # RBAC
    assert w["bob"].get("/api/admin/verify-chain").status_code == 403


def test_close_report_and_chain(world):
    w = world
    r = w["fac"].post(f"/api/sessions/{w['sid']}/close").json()
    assert cc.verify_report(r["report"], r["signature"])
    assert "DEMOALICE" in [p["usn"] for p in r["report"]["present"]]
    admin = logged_in("admin", "Admin@123")
    assert admin.get("/api/admin/verify-chain").json()["ok"]

    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("UPDATE attendance SET note = 'edited' WHERE id = 1")
    conn.commit()
    v = admin.get("/api/admin/verify-chain").json()
    assert not v["ok"] and v["problems"][0]["id"] == 1
    conn.execute("UPDATE attendance SET note = 'seeded history' WHERE id = 1")
    conn.commit()
    conn.close()
    assert admin.get("/api/admin/verify-chain").json()["ok"]


def test_lockout():
    c = TestClient(app)
    for _ in range(config.LOGIN_MAX_FAILS):
        c.post("/login", data={"username": "01FE23BCS171", "password": "nope"})
    r = c.post("/login", data={"username": "01FE23BCS171", "password": "Student@123"})
    assert r.status_code == 401 and "locked" in r.text.lower()
