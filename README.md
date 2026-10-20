# Work 1 — Secure REST API + CI/CD Security Scanning + CVE-2019-11043 Reproduction & Fix

Author: **Chen Yiming, HDU 23320218**.

This repository contains two parts:

1. **`/` (root)** — a hardened Flask REST API with OWASP Top-10 baseline protections, plus a GitHub Actions pipeline that runs SAST + SCA on every push.
2. **`/cve-2019-11043`** — reproduction, root-cause analysis, fix and verification of **CVE-2019-11043** (PHP-FPM 7.2 path-info buffer underflow → RCE behind nginx) from Vulhub.
3. *Appendix:* `/cve-ssti` — an additional Vulhub environment (Flask SSTI → RCE) that I studied before settling on CVE-2019-11043; kept here as supplementary material.

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

1. **SAST — Bandit**: static security analysis of the code; the verdict is printed to the job log and an HTML report is uploaded as a build artifact; medium+ severity findings fail the build.
2. **SCA — pip-audit** (PyPA): checks the pinned dependencies in `requirements.txt` against the PyPA vulnerability database; any known advisory fails the build.
   - This actually caught something: the initial pins (Flask 3.0.3, PyJWT 2.9.0) were flagged with 18 known advisories (e.g. PYSEC-2026-2151, PYSEC-2025-183). Upgrading to Flask 3.1.3 / PyJWT 2.15.0 cleared the audit — a concrete demonstration of why SCA belongs in the pipeline.
3. **Smoke test**: boots the API and asserts `/health` returns 200.

**Screenshots — all taken from the Actions page of run #17:**

![CI pipeline passing](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/screenshots/ci-pipeline-success.png)
*Run #17 — Status: Success, 38s, one artifact (`bandit-report`) produced.*

![Bandit SAST step log in GitHub Actions](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/screenshots/ci-bandit-log.png)
*The SAST step log inside the run: Bandit reports "No issues identified", 183 lines of code scanned and every severity counter (Undefined/Low/Medium/High) at zero, then writes `bandit-report.html` for the artifact. The single `#nosec B105` on the `"Bearer"` literal is a documented false positive — it is the HTTP auth scheme name, not a password.*

![pip-audit SCA step log in GitHub Actions](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/screenshots/ci-pip-audit-log.png)
*The SCA step log inside the run: pip-audit reports "No known vulnerabilities found" for the pinned dependencies.*

![Bandit HTML report](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/screenshots/bandit-report.png)
*The `bandit-report` artifact itself — 0 issues found (183 lines of code scanned). Kept as a second view of the same scan.*

**Pipeline link (last successful run):** https://github.com/ChenYiming-aaa/network-security-work1/actions/runs/39275027221


---

## Part 2 — CVE-2019-11043: Reproduction, Root Cause & Fix

### Chosen vulnerability

**CVE-2019-11043 — PHP-FPM (PHP 7.1.x < 7.1.33, 7.2.x < 7.2.24, 7.3.x < 7.3.11) path-info buffer underflow → unauthenticated RCE when deployed behind nginx with a `fastcgi_split_path_info` config that can pass an empty `PATH_INFO`.**

- **What it is**: when nginx passes a `PATH_INFO` FastCGI parameter whose value is **empty**, php-fpm's `init_request_info()` performs unchecked pointer arithmetic that underflows the FastCGI params buffer; the resulting out-of-bounds write primitive lets an attacker corrupt the memory layout so that part of a later FastCGI request is reinterpreted as **`PHP_VALUE` ini settings** (`allow_url_include=On`, `auto_prepend_file=php://input`), which executes the HTTP request body as PHP code.
- **Severity**: CVSS 3.1 **9.8 Critical** (NVD; the PHP Group as CNA rates it 8.7 High due to the `AC:H` configuration prerequisite). Actively exploited; present in CISA KEV.
- **Affects**: PHP 7.1.x below 7.1.33, 7.2.x below 7.2.24, 7.3.x below 7.3.11, in certain FPM + nginx configurations; fixed in **7.1.33 / 7.2.24 / 7.3.11**.
- **CWE**: CWE-120 (Classic Buffer Overflow).
- **Reported by**: Emil Lerner (PHP bug #78599); reference exploit `neex/phuip-fpizdam`.

### Environment

Vulhub `php/CVE-2019-11043`: an `nginx:1` service proxying to `vulhub/php:7.2.10-fpm`, with the stock misconfiguration `fastcgi_split_path_info ^(.+?\.php)(/.*)$` + `fastcgi_param PATH_INFO $fastcgi_path_info;` (which can send an empty `PATH_INFO`), published on port 8080.

```
$ cd vulhub/php/CVE-2019-11043 && docker compose up -d
$ docker ps
cve-2019-11043-nginx-1  nginx:1               Up  0.0.0.0:8080->80/tcp
cve-2019-11043-php-1    vulhub/php:7.2.10-fpm Up  9000/tcp
```

Raw output: `cve-2019-11043/evidence/reproduce_before_fix.log`.

### Reproduction (before fix)

Sanity check first: `curl -i http://localhost:8080/index.php` returns `HTTP 200` (`Server: nginx/1.31.7`, `X-Powered-By: PHP/7.2.10`) with the script's `hello world` output.

The exploit is `neex/phuip-fpizdam` (the reference implementation for this CVE). It runs in two phases:

1. **QSL detection** — probe `/PHP%0A….php?` + `Q`×n and record the query-string lengths that make the server answer `502` (those are the memory layouts where the underflowed write kills the worker):

```
2026/10/20 11:21:45 Base status code is 200
2026/10/20 11:21:46 The target is probably vulnerable. Possible QSLs: [1790 1795 1800]
```

2. **Attack** — with the right QSL and a path-info size offset, the zero-byte write lands where a later FastCGI param block is reinterpreted as `PHP_VALUE` (`allow_url_include=On`, `auto_prepend_file=php://input`), and the tool confirms code execution:

```
2026/10/20 11:21:48 Attack params found: --qsl 1795 --pisos 248 --skip-detect
2026/10/20 11:21:49 Success! Was able to execute a command by appending "?a=/bin/sh+-c+'which+which'&" to URLs
```

After a successful attack, commands run by appending `?a=/bin/sh+-c+'<cmd>'&` to any URL. Because php-fpm pools several workers and only a **poisoned** worker executes the injected settings, each probe is retried until a poisoned worker answers:

```bash
curl "http://localhost:8080/index.php?a=/bin/sh+-c+'whoami'&"      # -> www-data
curl "http://localhost:8080/index.php?a=/bin/sh+-c+'id'&"          # -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
curl "http://localhost:8080/index.php?a=/bin/sh+-c+'head+-n1+/etc/os-release'&"
# -> PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
```

**Screenshot — RCE (before fix):**

![RCE before fix](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-2019-11043/evidence/before-fix-rce.png)
*The exploit URL rendered in a browser session: the `id` command executed on the server — `uid=33(www-data) gid=33(www-data) groups=33(www-data)` — followed by the normal script output. Raw transcript: `cve-2019-11043/evidence/reproduce_before_fix.log`.*

### Root cause analysis

Full write-up: **`cve-2019-11043/root-cause-analysis.md`**. In my own words, short version:

The bug is an **unchecked pointer arithmetic on an empty `PATH_INFO` value** — a path-info buffer underflow. nginx still passes a `PATH_INFO` FastCGI parameter when `fastcgi_split_path_info` captures nothing (value empty); php-fpm assumed "the parameter exists" implies "the URL really is `script.php/pathinfo`" and computed the path-info pointer by subtracting the script-path length from a pointer into the FastCGI params buffer. With an empty value, the result points **before the start of the buffer**, and a subsequent write goes out of bounds. The attacker tunes the request size (query-string length — hence the QSL probing phase) to control where the write lands, realigns the heap so that a later request's FastCGI parameters are interpreted as **`PHP_VALUE` ini settings**, injects `allow_url_include=On` + `auto_prepend_file=php://input`, and turns the HTTP body into executed PHP — unauthenticated RCE as the php-fpm user.

The misconfiguration is what makes the trigger reachable (an empty `PATH_INFO` must actually reach php-fpm), and the code defect is what turns it into memory corruption: configuration decides reachability, the missing bounds check decides the impact.

### Fix

Files changed: `cve-2019-11043/fix/docker-compose.yml` (the vulnerable originals are archived in `cve-2019-11043/fix/original/` for comparison).

**Primary fix — upgrade the PHP image to the version where the CVE is fixed**: `image: vulhub/php:7.2.10-fpm` → `image: php:7.2.24-fpm` (7.2.24 contains the upstream fix for PHP bug #78599: `init_request_info()` now validates that the `PATH_INFO` value is consistent with the script filename before doing any pointer arithmetic, so the empty-`PATH_INFO` case can no longer produce an out-of-bounds pointer). The nginx service and the `default.conf` (including the misconfigured `fastcgi_split_path_info` block) are deliberately kept **identical** to the vulnerable environment — that way the verification below proves the attack dies because of the version fix itself, not because I hardened the configuration.

Defence-in-depth recommendations for a real deployment (not applied to the lab image on purpose): don't pass `PATH_INFO` when it can be empty (tighten the regex or add a `try_files $fastcgi_script_name =404;` guard), set `cgi.fix_pathinfo=0` if the app doesn't use path-info URLs, run php-fpm with least privileges, and pin images by digest — the floating `nginx:1` tag silently drifts (it resolved to nginx 1.31.7 here).

Applied with the standard cycle (`docker compose down` → edit `fix/docker-compose.yml` → `docker compose up -d`). Raw output: [`cve-2019-11043/evidence/verify_after_fix.log`](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-2019-11043/evidence/verify_after_fix.log) — `docker ps` shows the container Up and the banner is now `X-Powered-By: PHP/7.2.24`.

### Verification after fix (attack replay + regression)

The exact same payloads were replayed against PHP 7.2.24. Raw output: `cve-2019-11043/evidence/verify_after_fix.log`.

| Replay | Before fix (PHP 7.2.10) | After fix (PHP 7.2.24) |
|---|---|---|
| V1 `id` via `?a=/bin/sh+-c+'id'&` | `uid=33(www-data)…` | **`hello world` only — no command output (HTTP 200), 8/8 tries** |
| V2 `whoami` | `www-data` | **no command output** |
| V3 `head -n1 /etc/os-release` | `PRETTY_NAME="Debian GNU/Linux 9 (stretch)"` | **no command output** |
| V4 PoC detection phase (`phuip-fpizdam --only-qsl`) | `Possible QSLs: [1790 1795 1800]` — vulnerable | **`no qsl candidates found, invulnerable`** |

Regression tests: `GET /index.php` still returns `hello world` (200, `X-Powered-By: PHP/7.2.24`). Normal functionality is fully preserved.

**Screenshot — attack rejected after fix:**

![after fix rejected](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-2019-11043/evidence/after-fix-rejected.png)
*The exact URL that executed `id` on PHP 7.2.10 now returns only the normal script output — the injected `PHP_VALUE` settings are gone with the bounds check.*

**Screenshot — regression, normal page still works:**

![after fix regression](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-2019-11043/evidence/regression-ok.png)
*`http://localhost:8080/index.php` on the fixed server still returns the normal `hello world` page.*

---

## Appendix — extra environment studied (`/cve-ssti`)

Before choosing CVE-2019-11043 I reproduced an SSTI → RCE chain on the Vulhub `flask/ssti` environment (`{{233*233}}` → `54289`, gadget chain → `uid=33(www-data)`), analysed it (code/data confusion in `Template("Hello " + name)`) and fixed it (template-as-constant + input whitelist). Materials: `cve-ssti/` (evidence, `root-cause-analysis.md`, fix patch and layered verification). It is included as supplementary work; the graded CVE for this lab is **CVE-2019-11043** above.

**Before fix (vulnerable app mounted):** `/?name={{233*233}}` is evaluated server-side, and the Jinja2 gadget chain executes `id` on the server:

![SSTI before fix](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-ssti/evidence/before-fix-ssti.png)
*Address bar `localhost:8000/?name={{233*233}}` → `Hello 54289` on the vulnerable app.*

![SSTI RCE before fix](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-ssti/evidence/before-fix-rce.png)
*Terminal: the URL-encoded gadget chain runs `id` through `eval` — `uid=33(www-data)`.*

**After fix (patched app mounted):** the same payloads are rejected by the input whitelist before reaching the template engine, and normal requests still work:

![SSTI after fix rejected](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-ssti/evidence/after-fix-rejected.png)
*Same URL after the fix: `400 Bad Request — invalid characters in 'name' parameter`.*

![SSTI regression ok](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-ssti/evidence/regression-ok.png)
*Regression: `/?name=World` still returns `Hello World`.*

Raw transcripts: `cve-ssti/evidence/reproduce_before_fix.log`, `cve-ssti/evidence/verify_after_fix.log`.

One extra check worth showing, because the replay evidence above is all rejected by the whitelist and therefore does not *by itself* prove the primary fix works: I also built an intermediate version with the whitelist **removed** and only the code/data separation in place. `/?name={{233*233}}` then comes back as inert literal text (`Hello {{233*233}}`) instead of `Hello 54289`, and the RCE gadget chain produces no output — the separation alone neutralises the SSTI. Log: `cve-ssti/evidence/layered_fix_verification.log`.

![Layered verification](https://gcore.jsdelivr.net/gh/ChenYiming-aaa/network-security-work1@main/cve-ssti/evidence/layered-verification.png)
*Whitelist disabled, separation only: `{{233*233}}` renders as inert literal text — the primary fix works on its own.*

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
| CI pipeline link (last successful run) | https://github.com/ChenYiming-aaa/network-security-work1/actions/runs/39275027221 |
| Fixed files folder | `cve-2019-11043/fix/` (`docker-compose.yml`, original in `fix/original/`) |
| CVE reproduction & verification evidence | `cve-2019-11043/evidence/` (logs + screenshots) |
| Root cause analysis | `cve-2019-11043/root-cause-analysis.md` |
| Formal course report | `report/Work1_Report_Chen_Yiming_23320218.docx` |

## Notes

- README images are linked through **jsDelivr** (`gcore.jsdelivr.net/gh/…@main/…`) instead of relative paths: GitHub serves README images from `raw.githubusercontent.com`, which is not reliably reachable from mainland-China networks. The images live in this repository (identical files, same paths) — cloning the repo works exactly as usual.
- The Bandit HTML report is regenerated by every CI run and kept as the `bandit-report` artifact (downloadable from the run page); `screenshots/bandit-report.png` is the screenshot of that report.
- The Vulhub working clone (`vulhub/`) is kept outside the repository on purpose; only the reproduction/fix artifacts and evidence are committed.
