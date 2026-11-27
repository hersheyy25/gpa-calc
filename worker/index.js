/**
 * GPA Grimoire — Cloudflare Worker
 *
 * Username/password accounts (no email) with course storage in D1.
 * Same API shape as the Python dev server: /api/me, /api/signup, /api/login,
 * /api/logout, /api/courses (GET, PUT).
 *
 * Passwords: PBKDF2-HMAC-SHA256, 100k iterations, 16-byte per-user salt.
 * Sessions: random 256-bit token in an HttpOnly, SameSite=Lax cookie.
 */

const ITERATIONS = 100000;
const SESSION_SECONDS = 30 * 24 * 60 * 60;
const MAX_COURSES = 400;
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,24}$/;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 200;

const FAIL_LIMIT = 12;
const FAIL_WINDOW_MS = 10 * 60 * 1000;
const failures = new Map();

let schemaReady = null;

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function json(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return hex(buf);
}

function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function derive(password, saltHex) {
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map((h) => parseInt(h, 16)));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return hex(bits);
}

async function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = (async () => {
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS users (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           username TEXT NOT NULL UNIQUE,
           salt TEXT NOT NULL,
           pw_hash TEXT NOT NULL,
           created_at INTEGER NOT NULL
         )`
      ).run();
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS sessions (
           token TEXT PRIMARY KEY,
           user_id INTEGER NOT NULL,
           expires_at INTEGER NOT NULL
         )`
      ).run();
      await env.DB.prepare(
        `CREATE TABLE IF NOT EXISTS courses (
           user_id INTEGER PRIMARY KEY,
           data TEXT NOT NULL,
           updated_at INTEGER NOT NULL
         )`
      ).run();
      await env.DB.prepare(`CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id)`).run();
    })().catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

function readCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

function cookieHeader(request, token, maxAge = SESSION_SECONDS) {
  const secure = new URL(request.url).protocol === "https:" ? " Secure;" : "";
  return `sid=${token}; Path=/; HttpOnly;${secure} SameSite=Lax; Max-Age=${maxAge}`;
}

async function currentUser(env, request) {
  const token = readCookie(request, "sid");
  if (!token) return null;
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    `SELECT u.id AS id, u.username AS username, s.expires_at AS expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ?`
  ).bind(token).first();
  if (!row) return null;
  if (row.expires_at < now) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }
  return { id: row.id, username: row.username };
}

const GRADE_KEYS = ["sem1", "sem2", "q1", "q2", "q3", "q4"];

function cleanCourses(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];

  for (const item of raw.slice(0, MAX_COURSES)) {
    if (!item || typeof item !== "object") continue;
    const tier = Number(item.tier);
    if (![1, 2, 3].includes(tier)) continue;

    const yearNum = Number(item.year);
    const year = yearNum >= 7 && yearNum <= 12 ? yearNum : 9;

    const status = item.status === "current" ? "current" : "past";
    const semester = status === "current" ? (Number(item.semester) === 2 ? 2 : 1) : null;
    const credits = Number(item.credits) === 2 ? 2 : 1;
    const name = typeof item.name === "string" ? item.name.trim().slice(0, 60) : "";
    const id = typeof item.id === "string" || typeof item.id === "number"
      ? String(item.id).slice(0, 40)
      : randomToken(4);

    const grades = {};
    if (item.grades && typeof item.grades === "object") {
      for (const key of GRADE_KEYS) {
        const value = item.grades[key];
        if (value === null || value === undefined || value === "") continue;
        const n = Math.round(Number(value) * 10) / 10;
        if (Number.isFinite(n) && n >= 0 && n <= 100) grades[key] = n;
      }
    } else if (item.grade !== undefined) {
      // legacy single-grade course
      const g = item.grade === "below70" ? 69 : Math.round(Number(item.grade) * 10) / 10;
      if (Number.isFinite(g) && g >= 0 && g <= 100) {
        grades.sem1 = g;
        grades.sem2 = g;
      }
    }

    if (!Object.keys(grades).length) continue;

    out.push({ id, name, tier, credits, year, status, semester, grades });
  }
  return out;
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "unknown";
}

function throttled(request) {
  const ip = clientIp(request);
  const now = Date.now();
  const recent = (failures.get(ip) || []).filter((t) => now - t < FAIL_WINDOW_MS);
  failures.set(ip, recent);
  return recent.length >= FAIL_LIMIT;
}

function noteFailure(request) {
  const ip = clientIp(request);
  const list = (failures.get(ip) || []).filter((t) => Date.now() - t < FAIL_WINDOW_MS);
  list.push(Date.now());
  failures.set(ip, list);
}

/* ------------------------------------------------------------------ */
/* routes                                                              */
/* ------------------------------------------------------------------ */

async function readJson(request) {
  try {
    const text = await request.text();
    if (!text || text.length > 512 * 1024) return null;
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

async function handleApi(request, env, path) {
  const method = request.method;

  if (path === "/api/me" && method === "GET") {
    const user = await currentUser(env, request);
    return json({ username: user ? user.username : null });
  }

  if (path === "/api/courses" && method === "GET") {
    const user = await currentUser(env, request);
    if (!user) return json({ error: "not signed in" }, 401);
    const row = await env.DB.prepare("SELECT data FROM courses WHERE user_id = ?")
      .bind(user.id).first();
    const courses = row ? JSON.parse(row.data) : [];
    return json({ courses });
  }

  if (path === "/api/courses" && method === "PUT") {
    const user = await currentUser(env, request);
    if (!user) return json({ error: "not signed in" }, 401);
    const body = await readJson(request);
    if (!body) return json({ error: "invalid body" }, 400);

    const courses = cleanCourses(body.courses);
    await env.DB.prepare(
      `INSERT INTO courses (user_id, data, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`
    ).bind(user.id, JSON.stringify(courses), Math.floor(Date.now() / 1000)).run();

    return json({ ok: true, count: courses.length });
  }

  if (path === "/api/signup" && method === "POST") {
    if (throttled(request)) return json({ error: "Too many attempts. Try again in a few minutes." }, 429);

    const body = await readJson(request);
    if (!body) return json({ error: "invalid body" }, 400);

    const username = typeof body.username === "string" ? body.username.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";

    if (!USERNAME_RE.test(username)) {
      return json({ error: "Username must be 3-24 characters: letters, numbers, _ . or -" }, 400);
    }
    if (password.length < PASSWORD_MIN) {
      return json({ error: "Password must be at least 8 characters." }, 400);
    }
    if (password.length > PASSWORD_MAX) {
      return json({ error: "Password is too long." }, 400);
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE username = ? COLLATE NOCASE"
    ).bind(username).first();
    if (existing) return json({ error: "That username is already taken." }, 409);

    const salt = randomToken(16);
    const hash = await derive(password, salt);

    let userId;
    try {
      const res = await env.DB.prepare(
        "INSERT INTO users (username, salt, pw_hash, created_at) VALUES (?, ?, ?, ?)"
      ).bind(username, salt, hash, Math.floor(Date.now() / 1000)).run();
      userId = res.meta.last_row_id;
    } catch {
      return json({ error: "That username is already taken." }, 409);
    }

    const token = randomToken();
    await env.DB.prepare(
      "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
    ).bind(token, userId, Math.floor(Date.now() / 1000) + SESSION_SECONDS).run();

    return json({ username }, 200, { "Set-Cookie": cookieHeader(request, token) });
  }

  if (path === "/api/login" && method === "POST") {
    if (throttled(request)) return json({ error: "Too many attempts. Try again in a few minutes." }, 429);

    const body = await readJson(request);
    if (!body) return json({ error: "invalid body" }, 400);

    const username = typeof body.username === "string" ? body.username.trim() : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!username || !password) return json({ error: "Enter your username and password." }, 400);

    const row = await env.DB.prepare(
      "SELECT id, username, salt, pw_hash FROM users WHERE username = ? COLLATE NOCASE"
    ).bind(username).first();

    // Always hash, so a missing user costs the same as a wrong password.
    const candidate = await derive(password, row ? row.salt : "0".repeat(32));
    const ok = !!row && timingSafeEqual(candidate, row.pw_hash);

    if (!ok) {
      noteFailure(request);
      return json({ error: "Wrong username or password." }, 401);
    }

    const token = randomToken();
    await env.DB.prepare(
      "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
    ).bind(token, row.id, Math.floor(Date.now() / 1000) + SESSION_SECONDS).run();

    return json({ username: row.username }, 200, { "Set-Cookie": cookieHeader(request, token) });
  }

  if (path === "/api/logout" && method === "POST") {
    const token = readCookie(request, "sid");
    if (token) {
      await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    }
    return json({ ok: true }, 200, { "Set-Cookie": cookieHeader(request, "", 0) });
  }

  return json({ error: "not found" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      try {
        await ensureSchema(env);
        return await handleApi(request, env, url.pathname);
      } catch (err) {
        console.error("api error", url.pathname, err && err.stack ? err.stack : err);
        return json({ error: "Server error. Try again." }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
