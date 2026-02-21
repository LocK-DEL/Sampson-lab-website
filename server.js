const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sampson-lab-secret-key-2024';

// ============ SQLite 数据库初始化 ============
let db;
try {
  // 动态导入 better-sqlite3
  const Database = require('better-sqlite3');
  const dbPath = process.env.DATABASE_URL || path.join(__dirname, 'sampson.db');
  db = new Database(dbPath);
  console.log('✅ SQLite 数据库连接成功:', dbPath);
} catch (err) {
  console.error('❌ 数据库连接失败:', err);
  process.exit(1);
}

// 创建用户表
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'member',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// 检查并创建默认管理员
const adminExists = db.prepare('SELECT username FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const adminPassword = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)').run(
    uuidv4(),
    'admin',
    adminPassword,
    'admin'
  );
  console.log('✅ 默认管理员已创建: admin / admin123');
}

// ============ 中间件 ============
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ============ 工具函数 ============
const getUserByUsername = (username) => {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
};

const getAllUsers = () => {
  return db.prepare('SELECT id, username, role, created_at as createdAt FROM users ORDER BY created_at DESC').all();
};

const createUser = (username, password, role = 'member') => {
  const id = uuidv4();
  const passwordHash = bcrypt.hashSync(password, 10);
  try {
    db.prepare('INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)').run(id, username, passwordHash, role);
    return { success: true };
  } catch (err) {
    return { success: false, message: err.message };
  }
};

const deleteUser = (username) => {
  if (username === 'admin') return { success: false, message: '不能删除管理员' };
  try {
    db.prepare('DELETE FROM users WHERE username = ?').run(username);
    return { success: true };
  } catch (err) {
    return { success: false, message: err.message };
  }
};

// ============ 认证中间件 ============
const authenticate = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ authenticated: false, message: '请先登录' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ authenticated: false, message: '登录已过期' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  next();
};

// ============ 页面路由 ============

// 首页 - 需要登录
app.get('/', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// 登录页面 - 未登录时可见
app.get('/login.html', (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      jwt.verify(token, JWT_SECRET);
      return res.redirect('/');
    } catch {}
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

// 管理员页面 - 需要管理员权限
app.get('/admin.html', authenticate, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// 考试页面 - 需要登录
app.get('/exam.html', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'exam.html'));
});

// 静态文件
app.use(express.static(__dirname));

// ============ API 路由 ============

// 获取当前用户状态
app.get('/api/user', authenticate, (req, res) => {
  res.json({
    authenticated: true,
    username: req.user.username,
    isAdmin: req.user.role === 'admin'
  });
});

// 获取用户列表（仅管理员）
app.get('/api/users', authenticate, requireAdmin, (req, res) => {
  const users = getAllUsers();
  res.json({ success: true, users });
});

// 注册
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.json({ success: false, message: '用户名和密码不能为空' });
  }
  
  if (username.length < 3 || password.length < 6) {
    return res.json({ success: false, message: '用户名至少3字符，密码至少6字符' });
  }
  
  const result = createUser(username, password, 'member');
  if (result.success) {
    res.json({ success: true, message: '注册成功！请登录' });
  } else {
    res.json({ success: false, message: '用户名已存在' });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.json({ success: false, message: '用户名和密码不能为空' });
  }
  
  const user = getUserByUsername(username);
  if (!user) {
    return res.json({ success: false, message: '用户名或密码错误' });
  }
  
  const isValid = bcrypt.compareSync(password, user.password_hash);
  if (!isValid) {
    return res.json({ success: false, message: '用户名或密码错误' });
  }
  
  // 生成 JWT
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  // 设置 Cookie
  res.cookie('token', token, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  });
  
  res.json({
    success: true,
    message: '登录成功',
    isAdmin: user.role === 'admin'
  });
});

// 登出
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: '已退出登录' });
});

// 管理员添加用户
app.post('/api/admin/add-user', authenticate, requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  
  if (!username || !password) {
    return res.json({ success: false, message: '用户名和密码不能为空' });
  }
  
  if (username.length < 3 || password.length < 6) {
    return res.json({ success: false, message: '用户名至少3字符，密码至少6字符' });
  }
  
  const userRole = role === 'admin' ? 'admin' : 'member';
  const result = createUser(username, password, userRole);
  
  if (result.success) {
    res.json({ success: true, message: '用户添加成功' });
  } else {
    res.json({ success: false, message: '用户名已存在' });
  }
});

// 管理员删除用户
app.post('/api/admin/delete-user', authenticate, requireAdmin, (req, res) => {
  const { username } = req.body;
  const result = deleteUser(username);
  
  if (result.success) {
    res.json({ success: true, message: '用户删除成功' });
  } else {
    res.json({ success: false, message: result.message });
  }
});

// ============ 启动服务器 ============
app.listen(PORT, () => {
  console.log(`🚀 Sampson Lab 服务器运行在 http://localhost:${PORT}`);
});
