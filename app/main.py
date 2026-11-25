"""Secure QR-Based Attendance System — FastAPI app (pages + JSON API)."""
from __future__ import annotations

import io
import json
import re
import secrets
import sqlite3
import time
from datetime import datetime

import qrcode
import qrcode.image.svg
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import config, crypto_core as cc
from .db import append_attendance, chain_head, get_db, init_db, log_event, verify_chain
from .security import (
    client_ip, current_user, hash_password, ip_allowed, login, logout, require,
)

app = FastAPI(title="Secure QR Attendance", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=config.ROOT / "static"), name="static")
templates = Jinja2Templates(directory=config.ROOT / "templates")

init_db()
cc.ensure_signing_key()


# ---------------------------------------------------------------- security headers
@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; media-src 'self' blob:; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(self), geolocation=()"
    if request.url.scheme == "https":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


def fmt_ts(ts) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M:%S") if ts else "-"


templates.env.filters["ts"] = fmt_ts


def reject(reason: str, status: int = 400):
    return JSONResponse({"ok": False, "reason": reason}, status_code=status)


# ================================================================= PAGES
HOME_BY_ROLE = {"student": "/student", "faculty": "/faculty", "admin": "/admin"}


def page(request: Request, name: str, role: str | None = None, **ctx):
    user = current_user(request)
    if role and (not user or user["role"] != role):
        return RedirectResponse("/login", 303)
    return templates.TemplateResponse(request, name, {"user": user, **ctx})


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    return RedirectResponse(HOME_BY_ROLE[user["role"]] if user else "/login", 303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return page(request, "login.html", error=None)


@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    token, err = login(username.strip(), password, client_ip(request))
    if not token:
        return templates.TemplateResponse(request, "login.html", {"user": None, "error": err}, status_code=401)
    with get_db() as db:
        role = db.execute("SELECT role FROM users WHERE username = ?", (username.strip(),)).fetchone()["role"]
    resp = RedirectResponse(HOME_BY_ROLE[role], 303)
    resp.set_cookie(
        config.COOKIE_NAME, token, max_age=config.SESSION_TTL_SECONDS,
        httponly=True,                              # JS can't read it -> XSS can't steal it
        secure=request.url.scheme == "https",       # only sent over TLS
        samesite="strict",                          # not sent on cross-site requests -> CSRF
    )
    return resp


@app.post("/logout")
def logout_submit(request: Request):
    logout(request.cookies.get(config.COOKIE_NAME))
    resp = RedirectResponse("/login", 303)
    resp.delete_cookie(config.COOKIE_NAME)
    return resp


USN_RE = re.compile(r"^[0-9A-Z]{6,15}$")


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return page(request, "signup.html", error=None)


@app.post("/signup")
def signup_submit(request: Request, username: str = Form(...), name: str = Form(...), password: str = Form(...)):
    username = username.strip().upper()
    err = None
    if not USN_RE.match(username):
        err = "USN must be 6-15 letters/digits, e.g. 01FE23BCS106."
    elif len(password) < 8:
        err = "Password must be at least 8 characters."
    elif not name.strip():
        err = "Name is required."
    if not err:
        try:
            with get_db() as db:
                cur = db.execute(
                    "INSERT INTO users (username, name, role, pw_hash, created_at) VALUES (?,?,?,?,?)",
                    (username, name.strip(), "student", hash_password(password), time.time()),
                )
                # Demo convenience: new students are enrolled in every course.
                db.execute("INSERT INTO enrollments SELECT id, ? FROM courses", (cur.lastrowid,))
        except sqlite3.IntegrityError:
            err = "That USN is already registered."
    if err:
        return templates.TemplateResponse(request, "signup.html", {"user": None, "error": err}, status_code=400)
    return RedirectResponse("/login?registered=1", 303)


@app.get("/student", response_class=HTMLResponse)
def student_page(request: Request):
    return page(request, "student.html", role="student")


@app.get("/faculty", response_class=HTMLResponse)
def faculty_page(request: Request):
    return page(request, "faculty.html", role="faculty")


@app.get("/faculty/session/{sid}", response_class=HTMLResponse)
def session_page(request: Request, sid: str):
    return page(request, "session.html", role="faculty", sid=sid, period=config.QR_PERIOD)


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    return page(request, "admin.html", role="admin")


@app.get("/verify", response_class=HTMLResponse)
def verify_page(request: Request):
    return page(request, "verify.html")


# ================================================================= STUDENT API
@app.get("/api/me")
def me(user=Depends(require())):
    return {k: user[k] for k in ("id", "username", "name", "role", "device_fp")}


class DeviceReg(BaseModel):
    pubkey: str  # base64 SPKI of an ECDSA P-256 key generated in the browser


@app.post("/api/device/register")
def register_device(body: DeviceReg, request: Request, user=Depends(require("student"))):
    try:
        cc.load_device_pubkey(body.pubkey)
    except Exception:
        return reject("Invalid device public key")
    fp = cc.device_fingerprint(body.pubkey)
    with get_db() as db:
        if user["device_pubkey"] and user["device_fp"] != fp:
            log_event(db, "device_rebind_blocked", f"new fp {fp}", user_id=user["id"], ip=client_ip(request))
            return reject("Your account is already bound to another device. Ask the admin to reset it.", 409)
        db.execute("UPDATE users SET device_pubkey = ?, device_fp = ? WHERE id = ?", (body.pubkey, fp, user["id"]))
        log_event(db, "device_bound", fp, user_id=user["id"], ip=client_ip(request))
    return {"ok": True, "device_fp": fp}


class ScanReq(BaseModel):
    token: str   # QR content
    ts: int      # phone's unix time (seconds)
    nonce: str   # random, single use
    sig: str     # base64 raw ECDSA signature over scan_message(...)


NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


@app.post("/api/scan")
def scan(body: ScanReq, request: Request, user=Depends(require("student"))):
    ip = client_ip(request)
    with get_db() as db:
        def fail(reason: str, sid: str | None = None, status: int = 400):
            log_event(db, "scan_rejected", reason, session_id=sid, user_id=user["id"], ip=ip)
            return reject(reason, status)

        # 1. Network check (optional, set ALLOWED_SUBNETS)
        if not ip_allowed(ip):
            return fail("Not on the classroom network")

        # 2. Token authenticity + freshness (HMAC + time window)
        chk = cc.verify_qr_token(body.token)
        if not chk.ok:
            return fail(chk.reason, chk.session_id or None)
        sid = chk.session_id

        # 3. Session must be open and the student enrolled
        sess = db.execute("SELECT * FROM class_sessions WHERE id = ?", (sid,)).fetchone()
        if not sess or sess["closed_at"]:
            return fail("Session is not open", sid)
        if not db.execute(
            "SELECT 1 FROM enrollments WHERE course_id = ? AND student_id = ?", (sess["course_id"], user["id"])
        ).fetchone():
            return fail("Not enrolled in this course", sid, 403)

        # 4. Device binding: the request must be signed by THIS student's registered phone
        if not user["device_pubkey"]:
            return fail("No device registered for this account", sid, 403)
        if abs(time.time() - body.ts) > config.DEVICE_SIG_MAX_SKEW:
            return fail("Device clock / signature too old", sid)
        if not NONCE_RE.match(body.nonce):
            return fail("Bad nonce", sid)
        msg = cc.scan_message(body.token, user["id"], body.ts, body.nonce)
        if not cc.verify_device_signature(user["device_pubkey"], msg, body.sig):
            return fail("Signature does not match registered device (proxy attempt?)", sid, 403)

        # 5. Anti-replay of the signed request itself
        try:
            db.execute("INSERT INTO used_nonces (nonce, user_id, ts) VALUES (?,?,?)", (body.nonce, user["id"], time.time()))
            db.commit()
        except sqlite3.IntegrityError:
            return fail("Replayed request (nonce already used)", sid)

        # 6. Append to the tamper-evident chain (UNIQUE blocks double marking)
        try:
            rec = append_attendance(db, sid, user["id"], "qr", user["id"])
        except sqlite3.IntegrityError:
            return fail("Already marked present for this class", sid, 409)

    return {"ok": True, "message": "Attendance marked", "record_id": rec["id"], "hash": rec["hash"]}


def _course_stats(db, course_id: int) -> tuple[int, dict[int, int]]:
    total = db.execute("SELECT COUNT(*) c FROM class_sessions WHERE course_id = ?", (course_id,)).fetchone()["c"]
    rows = db.execute(
        "SELECT a.student_id, COUNT(*) c FROM attendance a JOIN class_sessions s ON s.id = a.session_id"
        " WHERE s.course_id = ? GROUP BY a.student_id",
        (course_id,),
    ).fetchall()
    return total, {r["student_id"]: r["c"] for r in rows}


@app.get("/api/me/attendance")
def my_attendance(user=Depends(require("student"))):
    out = []
    with get_db() as db:
        courses = db.execute(
            "SELECT c.* FROM courses c JOIN enrollments e ON e.course_id = c.id WHERE e.student_id = ?", (user["id"],)
        ).fetchall()
        for c in courses:
            total, counts = _course_stats(db, c["id"])
            present = counts.get(user["id"], 0)
            pct = round(100 * present / total, 1) if total else 100.0
            out.append({"code": c["code"], "name": c["name"], "present": present, "total": total, "pct": pct,
                        "defaulter": pct < config.DEFAULTER_THRESHOLD})
    return {"courses": out, "threshold": config.DEFAULTER_THRESHOLD}


# ================================================================= FACULTY API
def _own_session(db, sid: str, user) -> sqlite3.Row:
    sess = db.execute("SELECT * FROM class_sessions WHERE id = ?", (sid,)).fetchone()
    if not sess:
        raise HTTPException(404, "No such session")
    if user["role"] != "admin" and sess["faculty_id"] != user["id"]:
        raise HTTPException(403, "Not your session")
    return sess


@app.get("/api/faculty/overview")
def faculty_overview(user=Depends(require("faculty"))):
    with get_db() as db:
        courses = db.execute("SELECT * FROM courses WHERE faculty_id = ?", (user["id"],)).fetchall()
        out = []
        for c in courses:
            sessions = db.execute(
                "SELECT s.id, s.started_at, s.closed_at, (SELECT COUNT(*) FROM attendance a WHERE a.session_id = s.id) n"
                " FROM class_sessions s WHERE s.course_id = ? ORDER BY s.started_at DESC",
                (c["id"],),
            ).fetchall()
            enrolled = db.execute("SELECT COUNT(*) c FROM enrollments WHERE course_id = ?", (c["id"],)).fetchone()["c"]
            out.append({"id": c["id"], "code": c["code"], "name": c["name"], "enrolled": enrolled,
                        "sessions": [{**dict(s), "started": fmt_ts(s["started_at"])} for s in sessions]})
    return {"courses": out}


class StartReq(BaseModel):
    course_id: int


@app.post("/api/sessions")
def start_session(body: StartReq, user=Depends(require("faculty"))):
    with get_db() as db:
        c = db.execute("SELECT * FROM courses WHERE id = ? AND faculty_id = ?", (body.course_id, user["id"])).fetchone()
        if not c:
            raise HTTPException(403, "Not your course")
        sid = secrets.token_hex(4)
        db.execute(
            "INSERT INTO class_sessions (id, course_id, faculty_id, started_at) VALUES (?,?,?,?)",
            (sid, c["id"], user["id"], time.time()),
        )
    return {"ok": True, "session_id": sid}


def qr_svg(data: str) -> str:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=12, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


@app.get("/api/sessions/{sid}/live")
def session_live(sid: str, user=Depends(require("faculty"))):
    now = time.time()
    with get_db() as db:
        sess = _own_session(db, sid, user)
        course = db.execute("SELECT * FROM courses WHERE id = ?", (sess["course_id"],)).fetchone()
        present = db.execute(
            "SELECT a.id, a.ts, a.method, a.note, a.hash, u.username, u.name FROM attendance a"
            " JOIN users u ON u.id = a.student_id WHERE a.session_id = ? ORDER BY a.id DESC",
            (sid,),
        ).fetchall()
        rejected = db.execute(
            "SELECT e.ts, e.detail, u.username FROM security_events e LEFT JOIN users u ON u.id = e.user_id"
            " WHERE e.session_id = ? AND e.kind = 'scan_rejected' ORDER BY e.id DESC LIMIT 20",
            (sid,),
        ).fetchall()
        enrolled = db.execute("SELECT COUNT(*) c FROM enrollments WHERE course_id = ?", (course["id"],)).fetchone()["c"]
    closed = bool(sess["closed_at"])
    token = None if closed else cc.mint_qr_token(sid, now)
    return {
        "session_id": sid,
        "course": f"{course['code']} - {course['name']}",
        "closed": closed,
        "token": token,
        "qr_svg": qr_svg(token) if token else None,
        "expires_in": round(config.QR_PERIOD - (now % config.QR_PERIOD), 2),
        "period": config.QR_PERIOD,
        "enrolled": enrolled,
        "present": [{**dict(p), "time": fmt_ts(p["ts"])} for p in present],
        "rejected": [{**dict(r), "time": fmt_ts(r["ts"])} for r in rejected],
    }


class ManualReq(BaseModel):
    usn: str
    reason: str


@app.post("/api/sessions/{sid}/manual")
def manual_override(sid: str, body: ManualReq, request: Request, user=Depends(require("faculty"))):
    if len(body.reason.strip()) < 3:
        return reject("A reason is required for manual overrides")
    with get_db() as db:
        sess = _own_session(db, sid, user)
        if sess["closed_at"]:
            return reject("Session already closed")
        st = db.execute(
            "SELECT u.id FROM users u JOIN enrollments e ON e.student_id = u.id"
            " WHERE u.username = ? AND u.role = 'student' AND e.course_id = ?",
            (body.usn.strip().upper(), sess["course_id"]),
        ).fetchone()
        if not st:
            return reject("No enrolled student with that USN", 404)
        try:
            # Overrides go into the SAME chain, with the faculty as actor: fully auditable.
            rec = append_attendance(db, sid, st["id"], "manual", user["id"], body.reason.strip())
        except sqlite3.IntegrityError:
            return reject("Student already marked", 409)
        log_event(db, "manual_override", f"{body.usn}: {body.reason}", session_id=sid, user_id=user["id"],
                  ip=client_ip(request))
    return {"ok": True, "record_id": rec["id"]}


@app.post("/api/sessions/{sid}/close")
def close_session(sid: str, user=Depends(require("faculty"))):
    with get_db() as db:
        sess = _own_session(db, sid, user)
        if sess["closed_at"]:
            return reject("Already closed")
        closed_at = time.time()
        course = db.execute("SELECT * FROM courses WHERE id = ?", (sess["course_id"],)).fetchone()
        present = db.execute(
            "SELECT a.id, a.method, a.hash, u.username, u.name FROM attendance a JOIN users u ON u.id = a.student_id"
            " WHERE a.session_id = ? ORDER BY u.username",
            (sid,),
        ).fetchall()
        absent = db.execute(
            "SELECT u.username, u.name FROM enrollments e JOIN users u ON u.id = e.student_id"
            " WHERE e.course_id = ? AND u.id NOT IN (SELECT student_id FROM attendance WHERE session_id = ?)"
            " ORDER BY u.username",
            (course["id"], sid),
        ).fetchall()
        head, head_id = chain_head(db)
        report = {
            "type": "attendance-report-v1",
            "session_id": sid,
            "course": {"code": course["code"], "name": course["name"]},
            "faculty": {"username": user["username"], "name": user["name"]},
            "started_at": fmt_ts(sess["started_at"]),
            "closed_at": fmt_ts(closed_at),
            "present": [{"usn": p["username"], "name": p["name"], "method": p["method"],
                         "record_id": p["id"], "record_hash": p["hash"]} for p in present],
            "absent": [{"usn": a["username"], "name": a["name"]} for a in absent],
            "counts": {"present": len(present), "absent": len(absent)},
            "chain_head": head,        # anchors the whole log at this moment
            "chain_head_id": head_id,
        }
        sig = cc.sign_report(report)
        db.execute(
            "UPDATE class_sessions SET closed_at = ?, report_json = ?, report_sig = ? WHERE id = ?",
            (closed_at, cc.canonical_json(report).decode(), sig, sid),
        )
    return {"ok": True, "report": report, "signature": sig}


@app.get("/api/sessions/{sid}/report")
def get_report(sid: str, user=Depends(require("faculty", "admin"))):
    with get_db() as db:
        sess = _own_session(db, sid, user)
    if not sess["report_json"]:
        return reject("Session not closed yet", 404)
    body = {"report": json.loads(sess["report_json"]), "signature": sess["report_sig"],
            "algorithm": "Ed25519 over canonical JSON (sorted keys, no spaces)",
            "public_key": cc.public_key_pem()}
    return JSONResponse(body, headers={"Content-Disposition": f'attachment; filename="report-{sid}.json"'})


@app.get("/api/courses/{cid}/defaulters")
def defaulters(cid: int, user=Depends(require("faculty", "admin"))):
    with get_db() as db:
        c = db.execute("SELECT * FROM courses WHERE id = ?", (cid,)).fetchone()
        if not c or (user["role"] == "faculty" and c["faculty_id"] != user["id"]):
            raise HTTPException(403, "Not your course")
        total, counts = _course_stats(db, cid)
        students = db.execute(
            "SELECT u.id, u.username, u.name FROM enrollments e JOIN users u ON u.id = e.student_id"
            " WHERE e.course_id = ? ORDER BY u.username",
            (cid,),
        ).fetchall()
    rows = []
    for s in students:
        p = counts.get(s["id"], 0)
        pct = round(100 * p / total, 1) if total else 100.0
        rows.append({"usn": s["username"], "name": s["name"], "present": p, "total": total, "pct": pct,
                     "defaulter": pct < config.DEFAULTER_THRESHOLD})
    rows.sort(key=lambda r: r["pct"])
    return {"course": f"{c['code']} - {c['name']}", "threshold": config.DEFAULTER_THRESHOLD, "students": rows}


# ================================================================= PUBLIC VERIFY
@app.get("/api/pubkey")
def pubkey():
    return {"algorithm": "Ed25519", "public_key": cc.public_key_pem()}


class VerifyReq(BaseModel):
    report: dict
    signature: str


@app.post("/api/verify-report")
def verify_report(body: VerifyReq):
    return {"valid": cc.verify_report(body.report, body.signature)}


# ================================================================= ADMIN API
@app.get("/api/admin/verify-chain")
def admin_verify_chain(request: Request, user=Depends(require("admin"))):
    with get_db() as db:
        result = verify_chain(db)
        log_event(db, "chain_verified", "ok" if result["ok"] else f"{len(result['problems'])} problems",
                  user_id=user["id"], ip=client_ip(request))
    return result


@app.get("/api/admin/users")
def admin_users(user=Depends(require("admin"))):
    with get_db() as db:
        rows = db.execute(
            "SELECT id, username, name, role, device_fp, locked_until FROM users ORDER BY role, username"
        ).fetchall()
    now = time.time()
    return {"users": [{**dict(r), "locked": r["locked_until"] > now} for r in rows]}


@app.post("/api/admin/users/{uid}/reset-device")
def admin_reset_device(uid: int, request: Request, user=Depends(require("admin"))):
    with get_db() as db:
        db.execute("UPDATE users SET device_pubkey = NULL, device_fp = NULL WHERE id = ?", (uid,))
        log_event(db, "device_reset", f"user {uid}", user_id=user["id"], ip=client_ip(request))
    return {"ok": True}


@app.post("/api/admin/users/{uid}/unlock")
def admin_unlock(uid: int, user=Depends(require("admin"))):
    with get_db() as db:
        db.execute("UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?", (uid,))
    return {"ok": True}


class NewFaculty(BaseModel):
    username: str
    name: str
    password: str


@app.post("/api/admin/faculty")
def admin_new_faculty(body: NewFaculty, user=Depends(require("admin"))):
    if len(body.password) < 8:
        return reject("Password must be at least 8 characters")
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (username, name, role, pw_hash, created_at) VALUES (?,?,?,?,?)",
                (body.username.strip(), body.name.strip(), "faculty", hash_password(body.password), time.time()),
            )
    except sqlite3.IntegrityError:
        return reject("Username taken", 409)
    return {"ok": True}


@app.get("/api/admin/events")
def admin_events(user=Depends(require("admin"))):
    with get_db() as db:
        rows = db.execute(
            "SELECT e.*, u.username FROM security_events e LEFT JOIN users u ON u.id = e.user_id"
            " ORDER BY e.id DESC LIMIT 100"
        ).fetchall()
    return {"events": [{**dict(r), "time": fmt_ts(r["ts"])} for r in rows]}
