const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
}));

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

// 登录
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) return res.status(400).send('用户不存在');

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send('密码错误');

    req.session.userId = user.id;
    res.redirect('/profile');
  });
});

// 受保护的页面示例
app.get('/profile', (req, res) => {
  if (!req.session.userId) return res.status(401).send('未登录');

  db.get(`SELECT username FROM users WHERE id = ?`, [req.session.userId], (err, user) => {
    if (err || !user) return res.status(400).send('用户不存在');

    res.send(`欢迎你，${user.username}`);
  });
});

// 提供静态页面
app.use(express.static(path.join(__dirname, 'public')));

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`服务器启动 http://localhost:${PORT}`);
});
