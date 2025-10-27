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
  console.error("❌ 缺少 JWT_SECRET，请在 .env 中设置");
  process.exit(1);
}

// --- 数据库初始化 ---
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

// 如无管理员则自动创建
const adminExists = db.prepare("SELECT 1 FROM users WHERE email=? LIMIT 1").get(ADMIN_EMAIL);
if (!adminExists && ADMIN_EMAIL) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?,?, 'admin')")
    .run(ADMIN_EMAIL, hash);
  console.log(`✅ 已创建管理员账户：${ADMIN_EMAIL}（请尽快修改密码）`);
}

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS：开发期可 origin:true；上线后改成你的域名
app.use(cors({
  origin: true,              // 生产改为 "https://www.sampsonlab.space"
  credentials: true
}));

// 静态资源
app.use(express.static(path.join(__dirname, "public")));

// 将 /secure 目录保护起来（**把内部资料放这里**）
app.use("/secure", authMiddleware, express.static(path.join(__dirname, "secure")));

// 登录/鉴权限流：防暴力破解
const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 100 });

// —— 工具函数 —— //
function setAuthCookie(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: true, // 本地调试可临时改为 false；生产必须 true（HTTPS）
    maxAge: 7 * 24 * 3600 * 1000
  });
}

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "未登录" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "登录已过期，请重新登录" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "权限不足（仅管理员）" });
  }
  next();
}

// —— 账号与会话 —— //
// ⚠️ 公开注册已移除；仅管理员可创建用户

app.post("/api/login", authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "邮箱与密码必填" });

  const row = db.prepare("SELECT * FROM users WHERE email=?").get(email.toLowerCase());
  if (!row) return res.status(401).json({ error: "邮箱或密码错误" });

  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: "邮箱或密码错误" });

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

// —— 管理员接口：用户管理 —— //
app.get("/api/admin/users", authMiddleware, requireAdmin, (req, res) => {
  const list = db.prepare("SELECT id, email, role, created_at FROM users ORDER BY created_at DESC").all();
  res.json({ users: list });
});

app.post("/api/admin/users", authMiddleware, requireAdmin, async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "邮箱与密码必填" });
  if (role && !["admin", "member"].includes(role)) {
    return res.status(400).json({ error: "角色必须是 admin 或 member" });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users (email, password_hash, role) VALUES (?,?,?)")
      .run(email.toLowerCase(), hash, role || "member");
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) {
    if (String(e).includes("UNIQUE")) return res.status(409).json({ error: "该邮箱已存在" });
    res.status(500).json({ error: "创建失败" });
  }
});

app.patch("/api/admin/users/:id", authMiddleware, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { password, role } = req.body || {};
  if (!password && !role) return res.status(400).json({ error: "请提供要修改的字段" });

  try {
    if (password) {
      const hash = await bcrypt.hash(password, 12);
      db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash, id);
    }
    if (role) {
      if (!["admin", "member"].includes(role)) {
        return res.status(400).json({ error: "角色必须是 admin 或 member" });
      }
      db.prepare("UPDATE users SET role=? WHERE id=?").run(role, id);
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "更新失败" });
  }
});

app.delete("/api/admin/users/:id", authMiddleware, requireAdmin, (req, res) => {
  const { id } = req.params;
  if (req.user.id === Number(id)) return res.status(400).json({ error: "不能删除自己" });
  db.prepare("DELETE FROM users WHERE id=?").run(id);
  res.json({ ok: true });
});

// —— 受保护页面的“兜底”路由（可选）：阻止直接访问 admin.html 时未登录 —— //
// 前端 admin.html 会自行检测 /api/me 且必须 admin，否则跳回 login。
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.listen(PORT, () => {
  console.log(`🔐 Auth server running at http://localhost:${PORT}`);
});
