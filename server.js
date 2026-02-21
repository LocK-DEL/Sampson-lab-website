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
  fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));
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

// 认证中间件 - 检查是否登录
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

// 公开静态文件（首页、登录页等）
app.use(express.static(__dirname, {
  index: 'login.html',  // 默认显示登录页
  extensions: ['html']
}));

// 登录页面 - 公开访问
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// 登录页面 - 也支持 /login.html
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// 受保护的静态文件服务 - 需要登录
const protectedStatic = express.static(__dirname, {
  setHeaders: (res, filePath) => {
    // 检查是否是受保护的文件
    const protectedFiles = ['index.html', 'exam.html', 'style.css', 'script.js', 'home.js', 'auth.css', 'exam.css'];
    const fileName = path.basename(filePath);
    
    if (protectedFiles.includes(fileName)) {
      // 让前端处理重定向
      res.set('X-Require-Auth', 'true');
    }
  }
});

// CSRF Token 端点
app.get('/csrf-token', (req, res) => {
  const token = uuidv4();
  res.json({ csrfToken: token });
});

// 注册端点
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: '用户名和密码不能为空' 
      });
    }
    
    if (username.length < 3 || password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: '用户名至少3字符，密码至少6字符' 
      });
    }
    
    const users = getUsers();
    
    // 检查用户是否存在
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ 
        success: false, 
        message: '用户名已存在' 
      });
    }
    
    // 加密密码
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 创建用户
    const newUser = {
      id: uuidv4(),
      username,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    saveUsers(users);
    
    res.json({ 
      success: true, 
      message: '注册成功！请登录' 
    });
    
  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ 
      success: false, 
      message: '服务器错误' 
    });
  }
});

// 登录端点
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        message: '用户名和密码不能为空' 
      });
    }
    
    const users = getUsers();
    const user = users.find(u => u.username === username);
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: '用户名或密码错误' 
      });
    }
    
    // 验证密码
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.status(401).json({ 
        success: false, 
        message: '用户名或密码错误' 
      });
    }
    
    // 生成 JWT
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    // 设置 Cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7天
      sameSite: 'lax'
    });
    
    // 生成新的 CSRF token
    const csrfToken = uuidv4();
    
    res.json({ 
      success: true, 
      message: '登录成功',
      csrfToken,
      redirect: '/index.html'
    });
    
  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ 
      success: false, 
      message: '服务器错误' 
    });
  }
});

// 验证登录状态
app.get('/api/user', (req, res) => {
  const token = req.cookies.token;
  
  if (!token) {
    return res.status(401).json({ authenticated: false });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ authenticated: true, username: decoded.username });
  } catch {
    res.status(401).json({ authenticated: false });
  }
});

// 登出
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true, message: '已退出登录' });
});

// 受保护的 API 路由
app.get('/api/protected-data', requireAuth, (req, res) => {
  // 这里可以放置内部资料数据
  res.json({
    success: true,
    data: {
      message: '这是内部资料，只有登录用户才能查看',
      documents: [
        { name: '实验组内部手册.pdf', date: '2024-01-15' },
        { name: '成员通讯录.xlsx', date: '2024-02-01' },
        { name: '财务记录.pdf', date: '2024-01-20' }
      ]
    }
  });
});

// 检查是否需要登录中间件 - 用于前端页面
app.use((req, res, next) => {
  const token = req.cookies.token;
  const path = req.path;
  
  // 需要保护的页面
  const protectedPaths = ['/index.html', '/exam.html', '/home.js', '/script.js'];
  
  if (protectedPaths.includes(path) && !token) {
    return res.redirect('/login.html');
  }
  
  next();
});

// 启动服务器
app.listen(PORT, () => {
  console.log(`🚀 Sampson Lab 服务器运行在 http://localhost:${PORT}`);
  console.log(`📁 静态文件目录: ${__dirname}`);
});
