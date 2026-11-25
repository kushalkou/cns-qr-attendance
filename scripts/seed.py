"""Create demo users, courses and some past (signed) sessions.

    python -m scripts.seed           # only if the DB is empty
    python -m scripts.seed --reset   # wipe and recreate
"""
from __future__ import annotations

import random
import sys
import time

from app import config

if "--reset" in sys.argv and config.DB_PATH.exists():
    config.DB_PATH.unlink()

from app import main  # noqa: E402  (creates tables + signing key)
from app.db import append_attendance, get_db  # noqa: E402
from app.security import hash_password  # noqa: E402

ADMIN = ("admin", "System Admin", "Admin@123")
FACULTY = [("prof.rao", "Dr. Meera Rao", "Faculty@123"), ("prof.desai", "Dr. Arjun Desai", "Faculty@123")]
STUDENT_PW = "Student@123"
STUDENTS = [
    ("01FE23BCS106", "Kushal K"),
    ("01FE23BCS065", "Prateek J"),
    ("01FE23BCS221", "Sudarshan N"),
    ("01FE23BCS068", "Akash H"),
    ("01FE23BCS101", "Ananya Kulkarni"),
    ("01FE23BCS112", "Rohan Patil"),
    ("01FE23BCS130", "Sneha Hegde"),
    ("01FE23BCS144", "Varun Joshi"),
    ("01FE23BCS158", "Pooja Shetty"),
    ("01FE23BCS171", "Nikhil Bhat"),
    # used by scripts/attacks.py
    ("DEMOALICE", "Alice (demo)"),
    ("DEMOBOB", "Bob (demo, absent)"),
]
# chance each student attended a past class -> gives a realistic defaulter list
ATTEND_P = {"01FE23BCS106": 1.0, "01FE23BCS144": 0.45, "01FE23BCS171": 0.55, "DEMOBOB": 0.3}
COURSES = [("CNS", "Cryptography & Network Security", "prof.rao"), ("CN", "Computer Networks", "prof.desai")]
PAST_SESSIONS = 6


def main_seed() -> None:
    with get_db() as db:
        if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]:
            print("DB already seeded. Use --reset to start over.")
            return
        now = time.time()

        def add_user(username, name, role, pw):
            return db.execute(
                "INSERT INTO users (username, name, role, pw_hash, created_at) VALUES (?,?,?,?,?)",
                (username, name, role, hash_password(pw), now),
            ).lastrowid

        add_user(*ADMIN[:2], "admin", ADMIN[2])
        fac_ids = {u: add_user(u, n, "faculty", p) for u, n, p in FACULTY}
        stu_ids = {u: add_user(u, n, "student", STUDENT_PW) for u, n in STUDENTS}
        course_ids = {}
        for code, name, fac in COURSES:
            cid = db.execute("INSERT INTO courses (code, name, faculty_id) VALUES (?,?,?)", (code, name, fac_ids[fac])).lastrowid
            course_ids[code] = cid
            for sid in stu_ids.values():
                db.execute("INSERT INTO enrollments VALUES (?,?)", (cid, sid))
        db.commit()

        rng = random.Random(42)
        for code, _, fac in COURSES:
            fac_row = dict(db.execute("SELECT * FROM users WHERE id = ?", (fac_ids[fac],)).fetchone())
            for i in range(PAST_SESSIONS, 0, -1):
                sid = f"past{code.lower()}{i}"
                db.execute(
                    "INSERT INTO class_sessions (id, course_id, faculty_id, started_at) VALUES (?,?,?,?)",
                    (sid, course_ids[code], fac_ids[fac], now - i * 86400 * 2),
                )
                db.commit()
                for usn, uid in stu_ids.items():
                    if rng.random() < ATTEND_P.get(usn, 0.9):
                        append_attendance(db, sid, uid, "qr", uid, "seeded history")
                main.close_session(sid, user=fac_row)  # same code path as the real button -> signed report

    print("Seeded. Logins:")
    print(f"  admin      {ADMIN[0]:<14} {ADMIN[2]}")
    for u, _, p in FACULTY:
        print(f"  faculty    {u:<14} {p}")
    print(f"  students   01FE23BCS106 … {STUDENT_PW}  (all students share this demo password)")


if __name__ == "__main__":
    main_seed()
