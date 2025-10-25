const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const IN_PRODUCTION = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET || 'secret-key';
const SESSION_NAME = process.env.SESSION_NAME || 'sid';
const SESSION_DOMAIN = process.env.SESSION_DOMAIN;
const SESSION_MAX_AGE = Number(process.env.SESSION_MAX_AGE) || 1000 * 60 * 60 * 24; // 24 小时

const buildCookieOptions = (withMaxAge = false) => {
  const options = {
    httpOnly: true,
    secure: IN_PRODUCTION,
    sameSite: IN_PRODUCTION ? 'lax' : 'lax',
    path: '/',
  };

  if (withMaxAge) {
    options.maxAge = SESSION_MAX_AGE;
  }

  if (SESSION_DOMAIN) {
    options.domain = SESSION_DOMAIN;
  }

  return options;
};

if (IN_PRODUCTION) {
  app.set('trust proxy', 1);
}

app.use(
  session({
    name: SESSION_NAME,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: buildCookieOptions(true),
  })
);

const generateCsrfToken = (session) => {
  if (!session) {
    return null;
  }

  if (!session.csrfToken) {
    session.csrfToken = crypto.randomBytes(32).toString('hex');
  }

  return session.csrfToken;
};

const csrfProtection = (req, res, next) => {
  const method = req.method;
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return next();
  }

  const expectedToken = req.session && req.session.csrfToken;
  const headerToken =
    req.get('x-csrf-token') || req.get('csrf-token') || req.get('x-xsrf-token');
  const bodyToken = req.body && (req.body._csrf || req.body.csrfToken);
  const providedToken = headerToken || bodyToken;

  if (!expectedToken || !providedToken) {
    return res
      .status(403)
      .json({ success: false, message: 'CSRF token 缺失或无效' });
  }

  try {
    const expectedBuffer = Buffer.from(expectedToken, 'utf8');
    const providedBuffer = Buffer.from(providedToken, 'utf8');

    if (
      expectedBuffer.length === providedBuffer.length &&
      crypto.timingSafeEqual(expectedBuffer, providedBuffer)
    ) {
      return next();
    }
  } catch (error) {
    // ignore and fall through to the error response
  }

  return res
    .status(403)
    .json({ success: false, message: 'CSRF token 验证失败' });
};

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

app.get('/csrf-token', (req, res) => {
  const token = generateCsrfToken(req.session);
  return res.json({ csrfToken: token });
});

app.use(csrfProtection);

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
  if (!username || !password) {
    return res
      .status(400)
      .json({ success: false, message: '用户名和密码不能为空' });
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: '登录失败，请稍后重试' });
    }

    if (!user) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ success: false, message: '密码错误' });
    }

    req.session.regenerate((sessionError) => {
      if (sessionError) {
        return res
          .status(500)
          .json({ success: false, message: '登录失败，请稍后重试' });
      }

      req.session.userId = user.id;
      const nextToken = generateCsrfToken(req.session);

      return res.json({
        success: true,
        message: '登录成功',
        redirect: '/profile',
        csrfToken: nextToken,
      });
    });
  });
});

app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.json({ success: true, message: '已退出登录' });
  }

  req.session.destroy((err) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: '注销失败，请稍后重试' });
    }

    res.clearCookie(SESSION_NAME, buildCookieOptions());

    if (req.accepts('json')) {
      return res.json({ success: true, message: '已退出登录' });
    }

    return res.redirect('/');
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
