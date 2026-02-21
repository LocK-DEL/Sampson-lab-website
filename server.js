const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sampson-lab-secret-key-2024';
const USERS_FILE = path.join(__dirname, 'users.json');

// 初始化用户数据文件
if (!fs.existsSync(USERS_FILE)) {
  // 默认创建管理员账号
  const defaultUsers = [
    {
      id: uuidv4(),
      username: 'admin',
      password: bcrypt.hashSync('admin123', 10),
      role: 'admin',
      createdAt: new Date().toISOString()
    }
  ];
  fs.writeFileSync(USERS_FILE, JSON.stringify(defaultUsers, null, 2));
  console.log('✅ 默认管理员账号已创建: admin / admin123');
}

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// 读取用户
const getUsers = () => {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch {
    return [];
  }
};

// 保存用户
const saveUsers = (users) => {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// 认证中间件
const requireAuth = (req, res, next) => {
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

// 管理员中间件
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: '需要管理员权限' });
  }
  next();
};

// 公开页面
app.get('/login.html', (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      return res.redirect(decoded.role === 'admin' ? '/admin.html' : '/');
    } catch {}
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/login', (req, res) => {
  res.redirect('/login.html');
});

// 首页 - 需要登录
app.get('/', (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login.html');
  }
  try {
    jwt.verify(token, JWT_SECRET);
    res.sendFile(path.join(__dirname, 'index.html'));
  } catch {
    res.redirect('/login.html');
  }
});

// 管理页 - 需要管理员权限
app.get('/admin.html', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login.html');
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'admin.html'));
  } catch {
    res.redirect('/login.html');
  }
});

// 静态文件
app.use(express.static(__dirname));

// ============ API 路由 ============

// 注册
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.json({ success: false, message: '用户名和密码不能为空' });
    }
    
    if (username.length < 3 || password.length < 6) {
      return res.json({ success: false, message: '用户名至少3字符，密码至少6字符' });
    }
    
    const users = getUsers();
    
    if (users.find(u => u.username === username)) {
      return res.json({ success: false, message: '用户名已存在' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword,
      role: 'user',  // 默认普通成员
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    saveUsers(users);
    
    res.json({ success: true, message: '注册成功！请登录' });
    
  } catch (error) {
    console.error('注册错误:', error);
    res.json({ success: false, message: '服务器错误' });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.json({ success: false, message: '用户名和密码不能为空' });
    }
    
    const users = getUsers();
    const user = users.find(u => u.username === username);
    
    if (!user) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }
    
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
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
    
  } catch (error) {
    console.error('登录错误:', error);
    res.json({ success: false, message: '服务器错误' });
  }
});

// 验证登录状态
app.get('/api/user', (req, res) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.json({ authenticated: false });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ 
      authenticated: true, 
      username: decoded.username,
      role: decoded.role,
      isAdmin: decoded.role === 'admin'
    });
  } catch {
    res.json({ authenticated: false });
  }
});

// 登出
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// ============ 管理员 API ============

// 获取用户列表
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const users = getUsers();
  res.json({
    success: true,
    users: users.map(u => ({
      id: u.id,
      username: u.username,
      role: u.role,
      createdAt: u.createdAt
    }))
  });
});

// 管理员添加用户
app.post('/api/admin/add-user', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    
    if (!username || !password) {
      return res.json({ success: false, message: '用户名和密码不能为空' });
    }
    
    if (username.length < 3 || password.length < 6) {
      return res.json({ success: false, message: '用户名至少3字符，密码至少6字符' });
    }
    
    const users = getUsers();
    
    if (users.find(u => u.username === username)) {
      return res.json({ success: false, message: '用户名已存在' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword,
      role: role === 'admin' ? 'admin' : 'user',
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    saveUsers(users);
    
    res.json({ success: true, message: '用户添加成功' });
    
  } catch (error) {
    res.json({ success: false, message: '服务器错误' });
  }
});

// 管理员删除用户
app.post('/api/admin/delete-user', requireAuth, requireAdmin, (req, res) => {
  const { username } = req.body;
  
  if (username === 'admin') {
    return res.json({ success: false, message: '不能删除超级管理员' });
  }
  
  let users = getUsers();
  const initialLength = users.length;
  users = users.filter(u => u.username !== username);
  
  if (users.length === initialLength) {
    return res.json({ success: false, message: '用户不存在' });
  }
  
  saveUsers(users);
  res.json({ success: true, message: '用户已删除' });
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`🚀 Sampson Lab 服务器运行在 http://localhost:${PORT}`);
  console.log(`📁 静态文件目录: ${__dirname}`);
});
