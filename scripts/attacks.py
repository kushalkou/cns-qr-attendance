"""Red-team demo: run real attacks against the running server and show each one fail.

    python -m scripts.attacks                       # against https://localhost:8443
    python -m scripts.attacks --base https://192.168.1.5:8443
    python -m scripts.attacks --fast                # skip the ~20s expiry wait

Uses demo accounts DEMOALICE (present in class) and DEMOBOB (absent friend) from the seed.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import secrets
import sqlite3
import sys
import time
import warnings

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app import config
from app.crypto_core import GENESIS_HASH, chain_hash, verify_report
from app.db import record_dict

warnings.filterwarnings("ignore")
G, R, Y, B, D, X = "\033[32m", "\033[31m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"
results: list[tuple[str, bool, str]] = []

ADMIN = ("admin", "Admin@123")
FACULTY = ("prof.rao", "Faculty@123")
ALICE = ("DEMOALICE", "Student@123")
BOB = ("DEMOBOB", "Student@123")


# ---------------------------------------------------------------- helpers
class Phone:
    """Simulates a phone's WebCrypto device key (same algorithm as static/js/device.js)."""

    def __init__(self, label: str):
        self.label = label
        self.key = ec.generate_private_key(ec.SECP256R1())

    def pub_b64(self) -> str:
        der = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(der).decode()

    def sign_scan(self, token: str, user_id: int) -> dict:
        ts = int(time.time())
        nonce = secrets.token_urlsafe(18)
        der = self.key.sign(f"{token}|{user_id}|{ts}|{nonce}".encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)  # convert to raw r||s like WebCrypto
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"token": token, "ts": ts, "nonce": nonce, "sig": base64.b64encode(raw).decode()}


def client(base: str) -> httpx.Client:
    return httpx.Client(base_url=base, verify=False, follow_redirects=False, timeout=15)


def login(base: str, creds) -> httpx.Client:
    c = client(base)
    r = c.post("/login", data={"username": creds[0], "password": creds[1]})
    if r.status_code != 303:
        sys.exit(f"{R}Login failed for {creds[0]} ({r.status_code}). Is the DB seeded and the server running?{X}")
    return c


def header(n: int, title: str, story: str) -> None:
    print(f"\n{B}[{n}] {title}{X}\n{D}    {story}{X}")


def expect(name: str, resp: httpx.Response, want_block: bool) -> None:
    try:
        body = resp.json()
    except Exception:
        body = {}
    reason = body.get("reason") or body.get("detail") or body.get("message") or ""
    blocked = resp.status_code >= 400
    good = blocked == want_block
    tag = (f"{G}BLOCKED{X}" if blocked else f"{G}ACCEPTED{X}") if good else f"{R}UNEXPECTED{X}"
    print(f"    -> HTTP {resp.status_code} {tag}  {reason}")
    results.append((name, good, reason))


def check(name: str, ok: bool, detail: str) -> None:
    print(f"    -> {G if ok else R}{'DETECTED' if ok else 'MISSED'}{X}  {detail}")
    results.append((name, ok, detail))


# ---------------------------------------------------------------- main
def run(base: str, fast: bool, db_path: str) -> None:
    print(f"{B}SecureAttend red-team suite{X}  target={base}")

    admin = login(base, ADMIN)
    users = {u["username"]: u for u in admin.get("/api/admin/users").json()["users"]}
    alice_id, bob_id = users["DEMOALICE"]["id"], users["DEMOBOB"]["id"]
    for uid in (alice_id, bob_id):
        admin.post(f"/api/admin/users/{uid}/unlock")
        admin.post(f"/api/admin/users/{uid}/reset-device")

    fac = login(base, FACULTY)
    course = next(c for c in fac.get("/api/faculty/overview").json()["courses"] if c["code"] == "CNS")
    sid = fac.post("/api/sessions", json={"course_id": course["id"]}).json()["session_id"]
    print(f"{D}setup: faculty opened session {sid}; Alice and Bob registered their own phones{X}")

    alice_phone, bob_phone = Phone("Alice's phone"), Phone("Bob's phone")
    alice = login(base, ALICE)
    bob = login(base, BOB)
    alice.post("/api/device/register", json={"pubkey": alice_phone.pub_b64()})
    bob.post("/api/device/register", json={"pubkey": bob_phone.pub_b64()})

    def live_token() -> str:
        return fac.get(f"/api/sessions/{sid}/live").json()["token"]

    # 0. baseline
    header(0, "Baseline: Alice is in class and scans honestly", "Should be ACCEPTED.")
    tok = live_token()
    alice_req = alice_phone.sign_scan(tok, alice_id)
    expect("Legitimate scan", alice.post("/api/scan", json=alice_req), want_block=False)

    # 1. double scan
    header(1, "Double marking", "Alice scans again to inflate her count.")
    expect("Double scan", alice.post("/api/scan", json=alice_phone.sign_scan(live_token(), alice_id)), True)

    # 2. replay the exact signed request
    header(2, "Request replay", "Attacker sniffed Alice's exact request and resends it byte-for-byte.")
    expect("Replay signed request", alice.post("/api/scan", json=alice_req), True)

    # 3. forged token
    header(3, "Forged QR token", "Attacker guesses the format and builds a token for the next window.")
    s, w, _ = live_token().split(".")
    forged = f"{s}.{int(w) + 1}.{base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b'=').decode()}"
    expect("Forged HMAC", bob.post("/api/scan", json=bob_phone.sign_scan(forged, bob_id)), True)

    # 4. proxy: Alice marks for Bob with Bob's password
    header(4, "Proxy attendance", "Bob is absent. He gave Alice his password; she logs in as Bob on HER phone.")
    expect("Proxy from friend's phone", bob.post("/api/scan", json=alice_phone.sign_scan(live_token(), bob_id)), True)

    # 5. device takeover
    header(5, "Device takeover", "Alice tries to re-register Bob's account to her own phone.")
    expect("Re-bind device", bob.post("/api/device/register", json={"pubkey": alice_phone.pub_b64()}), True)

    # 6. screenshot forwarded late
    header(6, "Screenshot relay", "Alice photographs the QR and WhatsApps it to Bob at home.")
    old = live_token()
    if fast:
        s, w, _ = old.split(".")
        print(f"{D}    --fast: asking server about a token from 3 windows ago{X}")
        from app.crypto_core import _token_mac  # noqa: only to build a correctly-signed but stale token
        old = f"{s}.{int(w) - 3}.{_token_mac(s, int(w) - 3)}"
    else:
        wait = 2 * config.QR_PERIOD + 1
        for i in range(wait, 0, -1):
            print(f"\r{D}    Bob receives it {i:2d}s later…{X}", end="", flush=True)
            time.sleep(1)
        print()
    expect("Expired QR", bob.post("/api/scan", json=bob_phone.sign_scan(old, bob_id)), True)

    # 7. RBAC
    header(7, "Privilege escalation", "Bob calls faculty and admin endpoints directly.")
    expect("Student closes session", bob.post(f"/api/sessions/{sid}/close"), True)
    expect("Student reads admin API", bob.get("/api/admin/verify-chain"), True)

    # 8. brute force
    header(8, "Password brute force", "Attacker tries passwords against Bob's account.")
    c = client(base)
    for i in range(config.LOGIN_MAX_FAILS):
        c.post("/login", data={"username": "DEMOBOB", "password": f"guess{i}"})
    r = c.post("/login", data={"username": "DEMOBOB", "password": BOB[1]})  # even the RIGHT password now fails
    print(f"    -> correct password after {config.LOGIN_MAX_FAILS} failures: HTTP {r.status_code}")
    check("Account lockout", r.status_code == 401 and "locked" in r.text.lower(), "account locked")
    admin.post(f"/api/admin/users/{bob_id}/unlock")

    # 9. report forgery
    header(9, "Report forgery", "Session closes; signed report issued. Someone edits it to add Bob.")
    fac.post(f"/api/sessions/{sid}/close")
    rep = fac.get(f"/api/sessions/{sid}/report").json()
    print(f"    original report verifies: {verify_report(rep['report'], rep['signature'], rep['public_key'])}")
    forged_rep = copy.deepcopy(rep["report"])
    forged_rep["present"].append({"usn": "DEMOBOB", "name": "Bob (demo, absent)", "method": "qr",
                                  "record_id": 0, "record_hash": "0" * 64})
    forged_rep["absent"] = [a for a in forged_rep["absent"] if a["usn"] != "DEMOBOB"]
    ok = admin.post("/api/verify-report", json={"report": forged_rep, "signature": rep["signature"]}).json()["valid"]
    check("Edited report", not ok, "signature INVALID on edited report")

    # 10/11. DB tampering
    header(10, "Database tampering", "Insider opens the SQLite file and changes Alice's record to Bob.")
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM attendance WHERE session_id = ? AND student_id = ?", (sid, alice_id)).fetchone()
        backup = [dict(r) for r in conn.execute("SELECT * FROM attendance WHERE id >= ? ORDER BY id", (row["id"],))]
        conn.execute("UPDATE attendance SET student_id = ? WHERE id = ?", (bob_id, row["id"]))
        conn.commit()
        v = admin.get("/api/admin/verify-chain").json()
        check("Naive DB edit", not v["ok"], "; ".join(f"#{p['id']} {p['problem']}" for p in v["problems"]))

        header(11, "Smart tampering", "Insider edits the row AND recomputes every hash after it.")
        prev = conn.execute("SELECT hash FROM attendance WHERE id < ? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
        prev = prev["hash"] if prev else GENESIS_HASH
        for r_ in conn.execute("SELECT * FROM attendance WHERE id >= ? ORDER BY id", (row["id"],)).fetchall():
            h = chain_hash(prev, record_dict(r_))
            conn.execute("UPDATE attendance SET prev_hash = ?, hash = ? WHERE id = ?", (prev, h, r_["id"]))
            prev = h
        conn.commit()
        v = admin.get("/api/admin/verify-chain").json()
        check("Recomputed chain", not v["ok"], "; ".join(f"#{p['id']} {p['problem']}" for p in v["problems"]))

        for b in backup:  # put everything back
            conn.execute("UPDATE attendance SET student_id = ?, prev_hash = ?, hash = ? WHERE id = ?",
                         (b["student_id"], b["prev_hash"], b["hash"], b["id"]))
        conn.commit()
        conn.close()
        v = admin.get("/api/admin/verify-chain").json()
        print(f"    {D}restored original rows -> chain ok: {v['ok']}{X}")
    except (sqlite3.Error, TypeError) as e:
        print(f"    {Y}skipped: cannot open DB at {db_path} ({e}). Run on the server machine or pass --db.{X}")

    # summary
    print(f"\n{B}Summary{X}")
    for name, good, why in results:
        print(f"  {G + '✓' if good else R + '✗'}{X} {name:<26} {D}{why[:70]}{X}")
    passed = sum(g for _, g, _ in results)
    print(f"\n{B}{passed}/{len(results)} behaved as expected{X}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="https://localhost:8443")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--db", default=str(config.DB_PATH))
    a = ap.parse_args()
    run(a.base.rstrip("/"), a.fast, a.db)
