#!/usr/bin/env python3
"""GPA Grimoire server: static site + username/password accounts + SQLite storage.

Zero dependencies (Python standard library only).
"""

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC_ROOT = os.path.join(ROOT, "public")
DB_PATH = os.path.join(ROOT, "data", "gpa.db")
PORT = int(os.environ.get("PORT", "3000"))

PBKDF2_ROUNDS = 240_000
SESSION_SECONDS = 30 * 24 * 60 * 60
MAX_BODY = 512 * 1024
MAX_COURSES = 400

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,24}$")
PASSWORD_MIN = 8
PASSWORD_MAX = 200

FAILS = {}  # ip -> [timestamps] for sign-in throttling
FAIL_WINDOW = 10 * 60
FAIL_LIMIT = 12


# --------------------------------------------------------------------------
# database
# --------------------------------------------------------------------------

@contextlib.contextmanager
def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id         INTEGER PRIMARY KEY AUTOINCREMENT,
              username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
              salt       BLOB NOT NULL,
              pw_hash    BLOB NOT NULL,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token      TEXT PRIMARY KEY,
              user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS courses (
              user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
              data       TEXT NOT NULL,
              updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
            """
        )


def derive(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


# --------------------------------------------------------------------------
# course validation
# --------------------------------------------------------------------------

GRADE_KEYS = ("sem1", "sem2", "q1", "q2", "q3", "q4")


def _as_grade(value):
    try:
        n = round(float(value), 1)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 100 else None


def clean_courses(raw):
    """Accept only well-formed courses; mirrors the Worker's validation."""
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw[:MAX_COURSES]:
        if not isinstance(item, dict):
            continue
        try:
            tier = int(item.get("tier"))
        except (TypeError, ValueError):
            continue
        if tier not in (1, 2, 3):
            continue

        try:
            year = int(item.get("year"))
        except (TypeError, ValueError):
            year = 9
        if year < 7 or year > 12:
            year = 9

        status = "current" if item.get("status") == "current" else "past"
        semester = (2 if item.get("semester") in (2, "2") else 1) if status == "current" else None

        grades = {}
        src = item.get("grades")
        if isinstance(src, dict):
            for key in GRADE_KEYS:
                value = src.get(key)
                if value is None or value == "":
                    continue
                n = _as_grade(value)
                if n is not None:
                    grades[key] = n
        elif item.get("grade") is not None:
            legacy = item.get("grade")
            n = _as_grade(69 if legacy == "below70" else legacy)
            if n is not None:
                grades["sem1"] = n
                grades["sem2"] = n

        if not grades:
            continue

        credits = 2 if item.get("credits") in (2, "2") else 1
        name = item.get("name")
        name = name.strip()[:60] if isinstance(name, str) else ""
        cid = item.get("id")
        cid = str(cid)[:40] if isinstance(cid, (str, int)) else secrets.token_hex(4)

        out.append({
            "id": cid,
            "name": name,
            "tier": tier,
            "credits": credits,
            "year": year,
            "status": status,
            "semester": semester,
            "grades": grades,
        })
    return out


# --------------------------------------------------------------------------
# http handler
# --------------------------------------------------------------------------

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "GPAGrimoire"

    # ---------- helpers ----------

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

    def _json(self, code, payload, extra=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _cookie(self, name):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return None

    def _is_https(self):
        return (self.headers.get("X-Forwarded-Proto") or "").lower() == "https"

    def _session_cookie(self, token, max_age=SESSION_SECONDS):
        cookie = "sid=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d" % (token, max_age)
        if self._is_https():
            cookie += "; Secure"
        return cookie

    def _current_user(self):
        token = self._cookie("sid")
        if not token:
            return None
        now = int(time.time())
        with db() as conn:
            row = conn.execute(
                "SELECT u.id, u.username, s.expires_at FROM sessions s "
                "JOIN users u ON u.id = s.user_id WHERE s.token = ?",
                (token,),
            ).fetchone()
            if not row:
                return None
            if row["expires_at"] < now:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                return None
        return {"id": row["id"], "username": row["username"]}

    def _client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def _throttled(self):
        ip = self._client_ip()
        now = time.time()
        recent = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW]
        FAILS[ip] = recent
        return len(recent) >= FAIL_LIMIT

    def _note_failure(self):
        ip = self._client_ip()
        FAILS.setdefault(ip, []).append(time.time())

    def _new_session(self, conn, user_id):
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, int(time.time()) + SESSION_SECONDS),
        )
        return token

    # ---------- routes ----------

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/me":
            user = self._current_user()
            return self._json(200, {"username": user["username"] if user else None})

        if path == "/api/courses":
            user = self._current_user()
            if not user:
                return self._json(401, {"error": "not signed in"})
            with db() as conn:
                row = conn.execute(
                    "SELECT data FROM courses WHERE user_id = ?", (user["id"],)
                ).fetchone()
            data = json.loads(row["data"]) if row else []
            return self._json(200, {"courses": data})

        return self._static(path)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/signup":
            return self._signup()
        if path == "/api/login":
            return self._login()
        if path == "/api/logout":
            token = self._cookie("sid")
            if token:
                with db() as conn:
                    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            return self._json(200, {"ok": True}, [("Set-Cookie", self._session_cookie("", 0))])

        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        path = urlparse(self.path).path
        if path != "/api/courses":
            return self._json(404, {"error": "not found"})

        user = self._current_user()
        if not user:
            return self._json(401, {"error": "not signed in"})

        payload = self._body()
        if payload is None or not isinstance(payload, dict):
            return self._json(400, {"error": "invalid body"})

        courses = clean_courses(payload.get("courses"))
        blob = json.dumps(courses)
        with db() as conn:
            conn.execute(
                "INSERT INTO courses (user_id, data, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
                (user["id"], blob, int(time.time())),
            )
        return self._json(200, {"ok": True, "count": len(courses)})

    # ---------- auth ----------

    def _signup(self):
        if self._throttled():
            return self._json(429, {"error": "Too many attempts. Try again in a few minutes."})

        data = self._body() or {}
        username = (data.get("username") or "").strip() if isinstance(data.get("username"), str) else ""
        password = data.get("password") if isinstance(data.get("password"), str) else ""

        if not USERNAME_RE.match(username):
            return self._json(400, {"error": "Username must be 3-24 characters: letters, numbers, _ . or -"})
        if len(password) < PASSWORD_MIN:
            return self._json(400, {"error": "Password must be at least 8 characters."})
        if len(password) > PASSWORD_MAX:
            return self._json(400, {"error": "Password is too long."})

        salt = secrets.token_bytes(16)
        pw_hash = derive(password, salt)

        try:
            with db() as conn:
                cur = conn.execute(
                    "INSERT INTO users (username, salt, pw_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, salt, pw_hash, int(time.time())),
                )
                user_id = cur.lastrowid
                token = self._new_session(conn, user_id)
        except sqlite3.IntegrityError:
            self._note_failure()
            return self._json(409, {"error": "That username is already taken."})

        return self._json(
            200,
            {"username": username},
            [("Set-Cookie", self._session_cookie(token))],
        )

    def _login(self):
        if self._throttled():
            return self._json(429, {"error": "Too many attempts. Try again in a few minutes."})

        data = self._body() or {}
        username = (data.get("username") or "").strip() if isinstance(data.get("username"), str) else ""
        password = data.get("password") if isinstance(data.get("password"), str) else ""

        if not username or not password:
            return self._json(400, {"error": "Enter your username and password."})

        with db() as conn:
            row = conn.execute(
                "SELECT id, username, salt, pw_hash FROM users WHERE username = ?", (username,)
            ).fetchone()

        # always spend the same work, whether or not the user exists
        salt = row["salt"] if row else b"\x00" * 16
        candidate = derive(password, salt)
        valid = bool(row) and hmac.compare_digest(candidate, row["pw_hash"])

        if not valid:
            self._note_failure()
            return self._json(401, {"error": "Wrong username or password."})

        with db() as conn:
            token = self._new_session(conn, row["id"])

        return self._json(
            200,
            {"username": row["username"]},
            [("Set-Cookie", self._session_cookie(token))],
        )

    # ---------- static files ----------

    def _static(self, path):
        rel = path.lstrip("/") or "index.html"
        if rel.endswith("/"):
            rel += "index.html"

        parts = rel.split("/")
        if any(part.startswith(".") for part in parts) or parts[0] == "data":
            return self._json(404, {"error": "not found"})

        full = os.path.normpath(os.path.join(STATIC_ROOT, rel))
        if not full.startswith(STATIC_ROOT + os.sep) or not os.path.isfile(full):
            return self._json(404, {"error": "not found"})

        ext = os.path.splitext(full)[1].lower()
        if ext not in STATIC_TYPES:
            # never serve source, the database, or anything not meant for the browser
            return self._json(404, {"error": "not found"})

        with open(full, "rb") as handle:
            body = handle.read()

        self.send_response(200)
        self.send_header("Content-Type", STATIC_TYPES[ext])
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


def main():
    init_db()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("GPA Grimoire listening on http://0.0.0.0:%d" % PORT, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
