const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();

// 中间件设置
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
}));

// 初始化数据库（内存型）
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);
});

// ✅ 注册：成功后跳转到登录页
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('缺少用户名或密码');

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
    if (err) {
      return res.status(400).send('用户名已存在');
    }
    res.redirect('/login.html');  // ✅ 注册成功后跳转到登录页
  });
});

// ✅ 登录：成功后跳转主页
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) return res.status(400).send('用户不存在');

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send('密码错误');

    req.session.userId = user.id;
    res.redirect('/index.html');  // ✅ 登录成功后跳转到首页
  });
});

// 登出
app.post('/logout', (req, res) => {
  req.session.destroy();
  res.send('已退出登录');
});

// 受保护页面示例
app.get('/profile', (req, res) => {
  if (!req.session.userId) return res.status(401).send('未登录');

  db.get(`SELECT username FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user) return res.status(400).send('用户不存在');
    res.send(`欢迎你，${user.username}`);
  });
});

// 提供静态页面
app.use(express.static(path.join(__dirname, 'public')));

// 启动服务器
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`服务器启动 http://localhost:${PORT}`);
});
