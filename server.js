import express from "express";
import helmet from "helmet";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe_123";

if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in .env");
  process.exit(1);
}

// SQLite schema
const db = new Database("db.sqlite");
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin','member')) NOT NULL DEFAULT 'member',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// Bootstrap admin
if (ADMIN_EMAIL) {
  const exists = db.prepare("SELECT 1 FROM users WHERE email=?").get(ADMIN_EMAIL);
  if (!exists) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
    db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?,?, 'admin')").run(ADMIN_EMAIL, hash);
    console.log(`✅ Admin created: ${ADMIN_EMAIL} (please change password ASAP)`);
  }
}

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS: set your domain in production
app.use(cors({
  origin: true,            // e.g. "https://www.sampsonlab.space"
  credentials: true
}));

// Rate limit for login
const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 100 });

// Helpers
function setAuthCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true, // dev 可改为 false；生产必须 HTTPS + true
    maxAge: 7 * 24 * 3600 * 1000
  });
}

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "unauthenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "expired" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }
  next();
}

// Auth (no public register)
app.post("/api/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  const row = db.prepare("SELECT * FROM users WHERE email=?").get(email.toLowerCase());
  if (!row) return res.status(401).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });
  setAuthCookie(res, { id: row.id, email: row.email, role: row.role });
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token", { httpOnly: true, sameSite: "lax", secure: true });
  res.json({ ok: true });
});

app.get("/api/me", authMiddleware, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email, role: req.user.role } });
});

// Admin user management
app.get("/api/admin/users", authMiddleware, requireAdmin, (req, res) => {
  const list = db.prepare("SELECT id, email, role, created_at FROM users ORDER BY created_at DESC").all();
  res.json({ users: list });
});

app.post("/api/admin/users", authMiddleware, requireAdmin, async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  if (role && !["admin","member"].includes(role)) return res.status(400).json({ error: "invalid role" });
  try {
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?,?,?)")
      .run(email.toLowerCase(), hash, role || "member");
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) {
    if (String(e).includes("UNIQUE")) return res.status(409).json({ error: "email exists" });
    res.status(500).json({ error: "failed" });
  }
});

app.patch("/api/admin/users/:id", authMiddleware, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { password, role } = req.body || {};
  if (!password && !role) return res.status(400).json({ error: "no fields" });
  if (role && !["admin","member"].includes(role)) return res.status(400).json({ error: "invalid role" });
  try {
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash, id);
    }
    if (role) {
      db.prepare("UPDATE users SET role=? WHERE id=?").run(role, id);
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "failed" });
  }
});

app.delete("/api/admin/users/:id", authMiddleware, requireAdmin, (req, res) => {
  const { id } = req.params;
  if (req.user.id === Number(id)) return res.status(400).json({ error: "cannot delete self" });
  db.prepare("DELETE FROM users WHERE id=?").run(id);
  res.json({ ok: true });
});

// Protected static directory
app.use("/secure", authMiddleware, express.static(path.join(__dirname, "secure")));

// Admin page route
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

// Public static assets
app.use(express.static(path.join(__dirname, "public")));
app.get("/healthz", (req, res) => res.status(200).send("OK"));
app.listen(PORT, () => {
  console.log(`🔐 Auth server at http://localhost:${PORT}`);
});
