"""
Secure REST API - Network Security LAB Work 1

安全措施: 防 SQLi（参数化查询）、防 XSS（输出转义）、JWT + bcrypt 认证。
详见 README.md。
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

# 密钥只从环境变量读取，不设默认值：没配置就直接启动失败，避免误用弱密钥上线
if "JWT_SECRET" not in os.environ:
    raise RuntimeError(
        "JWT_SECRET environment variable is required. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = 30
# RFC 6749 token 响应里的认证方案名，协议常量而非密钥（避免 SAST 把 token_type 的值误报为硬编码密码）
BEARER_SCHEME = "Bearer"


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


# JWT 中间件：校验签名与过期时间；algorithms 白名单防止 alg 混淆攻击
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

    # bcrypt 自带随机盐 + 慢哈希，抗暴力破解；返回哈希前缀证明没存明文
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
                    "password_hash_prefix": password_hash[:29],
                },
            }
        ),
        201,
    )


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username") or ""
    password = data.get("password") or ""

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()

    # 用户不存在时也比对一次假哈希：让"用户不存在"和"密码错误"耗时一致，防时序侧信道
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
    return jsonify({"token": token, "token_type": BEARER_SCHEME, "expires_in": TOKEN_TTL_MINUTES * 60})


@app.get("/api/data")
@require_jwt
def get_data():
    db = get_db()
    rows = db.execute("SELECT id, author, title, body FROM posts ORDER BY id").fetchall()
    posts = [
        {
            "id": r["id"],
            "author": str(escape(r["author"])),  # 防 XSS：输出一律转义
            "title": str(escape(r["title"])),
            "body": str(escape(r["body"])),
        }
        for r in rows
    ]
    return jsonify({"posts": posts})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
