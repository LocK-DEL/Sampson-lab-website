const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
}));

const databaseDirectory = path.join(__dirname, 'data');
if (!fs.existsSync(databaseDirectory)) {
  fs.mkdirSync(databaseDirectory, { recursive: true });
}

const dbPath = path.join(databaseDirectory, 'app.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);
});

// 注册
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ success: false, message: '用户名和密码不能为空' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, hashedPassword],
      function (err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT') {
            return res
              .status(409)
              .json({ success: false, message: '用户名已存在' });
          }

          return res
            .status(500)
            .json({ success: false, message: '注册失败，请稍后重试' });
        }

        return res
          .status(201)
          .json({ success: true, message: '注册成功，欢迎加入！' });
      }
    );
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: '注册失败，请稍后重试' });
  }
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
