# SecureAttend: Secure QR-Based Attendance System

**Project page:** https://kushalkou.github.io/cns-qr-attendance/

CNS course project. The faculty laptop shows a QR code that changes every 10 seconds. A student's
**registered phone** scans it and signs the request with a key that never leaves the phone. The server
checks the HMAC, the time window, the device signature and a one-time nonce. It then appends the
record to a **hash chain**. Closing a session produces a report **signed with Ed25519**.

## Run

```bash
./run.sh            # first run: venv, deps, demo data, TLS cert, then serves on :8443
./run.sh --reset    # wipe DB and re-seed
pytest -q           # 7 tests
python -m scripts.attacks          # live red-team demo against the running server (server must be up)
python -m scripts.attacks --fast   # same, skips the 21 s expiry wait
python -m scripts.verify_report report-<id>.json   # offline signature check
```

Laptop: `https://localhost:8443`. Phones (same Wi-Fi): `https://<laptop-ip>:8443`. `run.sh` prints the
address. Accept the certificate warning once, because the cert is self-signed. HTTPS is mandatory:
phones only allow camera access and WebCrypto on secure pages.

| Role | Login | Password |
|---|---|---|
| Admin | `admin` | `Admin@123` |
| Faculty | `prof.rao` (CNS), `prof.desai` (CN) | `Faculty@123` |
| Students | `01FE23BCS106`, `01FE23BCS065`, … `DEMOALICE`, `DEMOBOB` | `Student@123` |

## Security mechanisms → deck claims

| # | Mechanism | Where | Stops |
|---|---|---|---|
| 1 | **Rotating HMAC token**: `sid.window.HMAC-SHA256(K_sid, sid‖window)[:16]`, window = ⌊t/10⌋, accepts current + previous window | `crypto_core.py` | forged QR, old screenshots |
| 2 | **HKDF key hierarchy**: master key in `.env` → per-session HMAC keys + key-wrap key | `config.py`, `crypto_core.derive_key` | one leaked key exposing everything |
| 3 | **Device binding**: WebCrypto ECDSA P-256 keypair (non-extractable) made on the phone; server stores only the public key; every scan is signed | `static/js/device.js`, `/api/device/register`, `/api/scan` | proxy with a friend's password |
| 4 | **Nonce + timestamp** on each signed scan | `/api/scan`, `used_nonces` | replay of a captured request |
| 5 | **Argon2id** passwords, lockout after 5 failures, generic error message | `security.py` | brute force, user enumeration, DB leak |
| 6 | **Sessions**: random 256-bit token, only its SHA-256 stored, HttpOnly + Secure + SameSite=Strict cookie, 2 h expiry | `security.py` | XSS cookie theft, CSRF, session hijack from DB leak |
| 7 | **RBAC**: `require('faculty')` etc. on every endpoint, plus ownership checks | `security.require`, `_own_session` | privilege escalation |
| 8 | **Hash-chained log**: `h_i = SHA256(h_{i-1} ‖ canonical(record_i))`; manual overrides go into the same chain with the faculty as actor | `db.py` | silent DB edits |
| 9 | **Ed25519 signed reports** that also pin the chain head; anyone can verify with the public key | `close_session`, `/verify` | report forgery, denial (non-repudiation) |
| 10 | Signing key **encrypted at rest** with an HKDF-derived key | `crypto_core.ensure_signing_key` | stolen key file |
| 11 | TLS, CSP, `X-Frame-Options`, `nosniff`, HSTS; all dynamic HTML escaped | `main.py` middleware, `common.js` | eavesdropping, XSS, clickjacking |
| 12 | Optional **subnet check** (`ALLOWED_SUBNETS` in `.env`) | `security.ip_allowed` | scanning from outside the classroom network |

## Scan verification order (`POST /api/scan`)

```
network allowed? → HMAC valid? → window fresh? → session open? → enrolled?
→ device registered? → timestamp within 60s? → ECDSA signature by bound device? → nonce unused?
→ append to hash chain (UNIQUE session+student blocks double marking)
```
Every rejection is logged to `security_events`. These appear live on the faculty screen and in the admin panel.

## Red-team demo (`scripts/attacks.py`), 13/13 blocked

| Attack | Result |
|---|---|
| Double scan | 409 already marked |
| Replay exact signed request | nonce already used |
| Forged token for next window | bad HMAC |
| Friend logs in as absent student on their own phone | signature ≠ registered device |
| Re-bind absent student's account to friend's phone | 409, admin reset required |
| Screenshot forwarded 21 s later | expired token |
| Student calls faculty/admin APIs | 403 |
| Password brute force | account locked (even correct password refused) |
| Edit signed report JSON | signature invalid |
| Edit a row in SQLite | hash mismatch at exact record |
| Edit row **and recompute the whole chain** | mismatch with head pinned in signed report |

## Threat model: what it does *not* stop
- A student physically handing their own phone to a friend in class. No QR system can stop this; it would need biometrics or a face check.
- A screenshot relayed **within** ~10–20 s to someone off-site. Narrow the window, or enable `ALLOWED_SUBNETS` so scans must come from college Wi-Fi.
- A compromised server: whoever holds the master key can mint tokens. That's why it lives only in `.env` (mode 600, git-ignored).
- Report signatures prove the **system** issued them. Per-faculty signing keys would be the next step.

## Layout
```
app/config.py        settings, .env + master key bootstrap
app/crypto_core.py   HKDF, QR tokens, ECDSA verify, hash chain, Ed25519
app/db.py            schema, chain append/verify
app/security.py      Argon2, sessions, RBAC, lockout
app/main.py          pages + JSON API
static/js/device.js  WebCrypto device key + scan signing
scripts/             seed, make_cert, attacks, verify_report
tests/               pytest suite
```
