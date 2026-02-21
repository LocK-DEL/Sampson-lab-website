# Sampson Lab Website

生物实验室官网

## 本地开发

### 安装依赖
```bash
npm install
```

### 启动服务器
```bash
npm start
```

访问 http://localhost:3000

### 配置环境变量 (可选)
创建 `.env` 文件：
```env
JWT_SECRET=你的密钥
PORT=3000
```

## 功能
- 用户注册/登录
- JWT 认证
- CSRF 保护

## 部署到 GitHub Pages

由于 GitHub Pages 只支持静态文件，需要把 `server.js` 部署到其他平台（如 Vercel、Railway、Render）来运行后端。

或者使用 GitHub Actions + Vercel 自动化部署。
