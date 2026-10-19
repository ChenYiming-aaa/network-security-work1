"""
Secure REST API - Network Security LAB Work 1

安全措施:
  1. 防 SQLi  : 全部使用 SQLite 参数化查询 (Prepared Statements)
  2. 防 XSS   : 所有返回给客户端的用户输入均经 markupsafe.escape 转义
  3. 认证     : JWT (PyJWT, 显式 HS256, 校验签名与过期时间) + bcrypt 密码哈希
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape

app = Flask(__name__)

DATABASE = os.environ.get("APP_DB_PATH", "users.db")
# 密钥从环境变量读取，绝不硬编码提交到仓库
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-secret-change-me")
JWT_ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = 30


# ---------------------------------------------------------------------------
# 数据库（每次请求一个连接，全部使用 ? 占位符参数化查询，防止 SQL 注入）
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    if db.execute("SELECT COUNT(*) FROM posts").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO posts (author, title, body) VALUES (?, ?, ?)",
            [
                ("alice", "First post", "Hello, secure world!"),
                ("bob", "Security notes", "Always use parameterized queries."),
            ],
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# JWT 认证中间件：校验签名、过期时间；显式限制算法，防止 alg 混淆攻击
# ---------------------------------------------------------------------------
def require_jwt(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Bearer token"}), 401
        token = auth[len("Bearer "):]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return fn(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# 端点 1: POST /api/users —— 用户注册（演示 bcrypt 密码哈希存储）
# ---------------------------------------------------------------------------
@app.post("/api/users")
def register_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    display_name = (data.get("display_name") or "").strip()

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    # bcrypt: 内置随机盐 + 慢哈希，抗暴力破解
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)",
            (username, password_hash, display_name or username),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409

    return (
        jsonify(
            {
                "message": "user registered",
                "user": {
                    "username": username,
                    "display_name": escape(display_name or username),
                    # 仅展示哈希前 29 位（$2b$12$ + 22 字符盐），证明密码未存明文
                    "password_hash_prefix": password_hash[:29],
                },
            }
        ),
        201,
    )


# ---------------------------------------------------------------------------
# 端点 2: POST /auth/login —— 验证凭据，签发 JWT
# ---------------------------------------------------------------------------
@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username") or ""
    password = data.get("password") or ""

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    # 用户不存在时也执行一次哈希比较，避免时序侧信道区分“用户不存在/密码错误”
    stored_hash = row["password_hash"].encode() if row else b"$2b$12$" + b"x" * 53
    try:
        ok = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except ValueError:
        ok = False

    if row is None or not ok:
        return jsonify({"error": "invalid credentials"}), 401

    payload = {
        "sub": str(row["id"]),  # PyJWT>=2.10 要求 sub 必须为字符串
        "username": row["username"],
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({"token": token, "token_type": "Bearer", "expires_in": TOKEN_TTL_MINUTES * 60})  # nosec B105 - "Bearer" 是 HTTP 认证方案名，不是密码


# ---------------------------------------------------------------------------
# 端点 3: GET /api/data —— 受 JWT 保护的数据接口（返回内容做 XSS 转义）
# ---------------------------------------------------------------------------
@app.get("/api/data")
@require_jwt
def get_data():
    db = get_db()
    rows = db.execute("SELECT id, author, title, body FROM posts ORDER BY id").fetchall()
    posts = [
        {
            "id": r["id"],
            "author": str(escape(r["author"])),   # 防 XSS：输出转义
            "title": str(escape(r["title"])),
            "body": str(escape(r["body"])),
        }
        for r in rows
    ]
    return jsonify({"posts": posts})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
