# Work 1 — Secure REST API + CI/CD Security Scanning + Real CVE Reproduction & Fix

Network Security LAB (HDU). Author: **Chen Yiming, HDU 23320218**.

This project contains **two parts**:

1. **`/` (this directory)** — a hardened Flask REST API with OWASP Top-10 baseline protections and a GitHub Actions CI pipeline running SAST + SCA on every push.
2. **`/cve-ssti`** — reproduction, root-cause analysis, fix and verification of a real-world server-side template injection (SSTI → RCE) vulnerability from Vulhub.

> **Variant / report title page:** see the course report template (Lab number & name, variant number, Surname and Name, HDU number).

---

## Part 1 — Secure REST API

### Tech stack

Python 3.12 / Flask 3, SQLite, PyJWT (HS256), bcrypt.

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/users` | — | Register a user. Password is hashed with **bcrypt** before storage. Returns the bcrypt hash *prefix* (`$2b$12$…`) as proof that no plaintext is stored. |
| POST | `/auth/login` | — | Verifies credentials (bcrypt `checkpw`), returns a **JWT** (HS256, 30 min expiry). |
| GET | `/api/data` | **JWT required** | Returns the posts list. All user-influenced output is HTML-escaped. |
| GET | `/health` | — | Liveness probe used by CI smoke test. |

### How to run & call

```bash
pip install -r requirements.txt
python app.py                      # listens on http://127.0.0.1:5000

# register
curl -X POST http://127.0.0.1:5000/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Str0ngPass!","display_name":"Alice"}'

# login -> JWT
curl -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"Str0ngPass!"}'

# access protected data (paste the token)
curl http://127.0.0.1:5000/api/data -H "Authorization: Bearer <JWT>"
```

### Security measures (grading points)

| Requirement | Implementation | Verified by |
|---|---|---|
| **SQLi prevention** | Every SQL statement uses SQLite **parameterized queries** (`?` placeholders) — user input is never concatenated into SQL. | Attack `' OR 1=1--` at login → `401 invalid credentials` (evidence log item [6]). |
| **XSS prevention** | All user-controlled output escaped via `markupsafe.escape()` before being returned. | Registered user with `display_name = <script>alert(1)</script>` → response contains `&lt;script&gt;…` (item [9]). |
| **Authentication** | **JWT** (PyJWT, explicit `HS256`, signature + `exp` verified by a decorator on protected endpoints; explicit algorithm whitelist blocks `alg`-confusion). Passwords hashed with **bcrypt** (random salt + slow hashing, resistant to brute force — unlike plain SHA-256). | No token → 401 [1]; forged token → 401 [2]; tampered signature → 401 [10]; valid token → 200 + data [8]. |

Full request/response evidence: `../evidence_api_verification.log` (10 test cases).

> `JWT_SECRET` is read from an environment variable — no secrets are committed.

### CI/CD — SAST + SCA (`.github/workflows/ci.yml`)

Triggers on **every push / pull request**:

1. **SAST — Bandit**: static security analysis of the code, HTML report uploaded as a build artifact; medium+ severity findings fail the build.
2. **SCA — pip-audit** (PyPA): checks the pinned dependencies in `requirements.txt` against the PyPA vulnerability database; any known CVE fails the build.
   - *Real catch*: the initial pins (Flask 3.0.3, PyJWT 2.9.0) were flagged with 18 known advisories (e.g. PYSEC-2026-2151, PYSEC-2025-183). Dependencies were upgraded to Flask 3.1.3 / PyJWT 2.15.0, after which the audit is clean — demonstrating exactly why SCA belongs in CI.
3. **Smoke test**: boots the API and asserts `/health` returns 200.

📎 *Screenshot placeholders (add after first successful run):*
- `![CI pipeline passing](screenshots/ci-pipeline-success.png)` — Actions run page (green)
- `![Bandit report](screenshots/bandit-report.png)` — Bandit HTML artifact
- `![pip-audit result](screenshots/pip-audit-report.png)` — pip-audit clean output (and the flagged run before the dependency upgrade, if captured)

**Pipeline link (last successful run):** `<FILL IN: https://github.com/<user>/<repo>/actions/runs/<id>>`

---

## Part 2 — CVE Reproduction, Root Cause & Fix (`/cve-ssti`)

### Chosen vulnerability

**Flask (Jinja2) Server-Side Template Injection (SSTI) → RCE** — Vulhub `flask/ssti`.
(Note: the manual's suggested `vulhub/flask/CVE-2018-1000656` no longer exists in
the official Vulhub repo; this equivalent Flask-stack environment was chosen instead.)

- **Class**: SSTI (CWE-1336) escalating to remote code execution; OWASP A03:2021 Injection.
- **Impact**: unauthenticated attacker executes arbitrary OS commands on the server (`www-data`).
- **Cause**: user input is concatenated into the Jinja2 template *source* — attacker-authored `{{…}}` expressions are executed server-side; via a Python gadget chain (`[].__class__.__base__.__subclasses__()` → `catch_warnings.__init__.__globals__` → `eval`) this becomes full RCE.

### Reproduction (before fix)

```bash
cd cve-ssti/vulhub/flask/ssti && docker compose up -d   # vulhub/flask:1.1.1 on :8000

curl 'http://localhost:8000/?name=World'        # -> Hello World
curl 'http://localhost:8000/?name={{233*233}}'  # -> Hello 54289   (SSTI confirmed)
# RCE POC (URL-encoded Jinja2 gadget chain -> eval -> os.popen("id").read()):
curl 'http://localhost:8000/?name=%7B%25%20for%20c%20in%20%5B%5D...'   # -> uid=33(www-data)...
```

Evidence: `cve-ssti/evidence/reproduce_before_fix.log` — expression evaluation **and** real command output (`id`, `head -n1 /etc/passwd`).

📎 *Screenshot placeholder:* `![SSTI before fix](cve-ssti/evidence/before-fix-browser.png)`

### Root cause analysis

See **`cve-ssti/root-cause-analysis.md`** — summary: the app confuses **code and data**. `Template("Hello " + name)` lets the attacker write part of a Jinja2 *program*, which the server executes; the unsandboxed `jinja2.Template` allows arbitrary Python object traversal, so template math escalates to RCE.

### Fix (`cve-ssti/fix/`)

1. **Primary — code/data separation**: template is a developer-owned constant; user input is only passed as a template *variable* (`render_template_string(TEMPLATE, name=name)` — autoescaped, rendered as inert text).
2. **Defence in depth**: `name` whitelisted to `[A-Za-z0-9 ._-]` (≤64 chars); anything else → HTTP 400 before reaching the template engine.

Patch: `cve-ssti/fix/app_fix.patch`. Changed file: `cve-ssti/fix/src/app.py` (drop-in replacement for the Vulhub-mounted `src/app.py`).

### Verification after fix (attack replay + regression)

Identical payloads replayed (`cve-ssti/evidence/verify_after_fix.log`):

| Attack | Before | After |
|---|---|---|
| `{{233*233}}` | `Hello 54289` | **400 rejected** |
| RCE POC (`id`) | `uid=33(www-data)…` | **400 rejected** |
| RCE POC (`/etc/passwd`) | `root:x:0:0:root…` | **400 rejected** |

Regression: `/?name=World` → `Hello World` (200), `/?name=Alice_2026` → works — normal functionality preserved.

📎 *Screenshot placeholders:* `![after fix rejected](cve-ssti/evidence/after-fix-rejected.png)`, `![regression ok](cve-ssti/evidence/regression-ok.png)`

---

## Submission checklist

| Item | Location |
|---|---|
| Public Git repository | `<FILL IN repo URL>` |
| This README | `README.md` |
| CI pipeline link (last successful run) | `<FILL IN actions URL>` |
| Fixed files folder | `cve-ssti/fix/` (`src/app.py`, `app_fix.patch`, before/after evidence) |

## Screenshot TODO list (manual)

1. `screenshots/ci-pipeline-success.png` — GitHub Actions green run
2. `screenshots/bandit-report.png` — Bandit HTML artifact
3. `cve-ssti/evidence/before-fix-browser.png` — browser/curl showing `Hello 54289` + `uid=33(...)`
4. `cve-ssti/evidence/after-fix-rejected.png` — same payload returning 400
5. `cve-ssti/evidence/regression-ok.png` — `Hello World` after fix
