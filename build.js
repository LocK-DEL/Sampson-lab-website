/**
 * build.js — 静态网站构建脚本
 * 将所有静态文件复制到 /out 目录，供直接部署使用。
 * 运行: node build.js  (或 npm run build / npm run export)
 */

const fs = require('fs');
const path = require('path');

const OUT_DIR = path.join(__dirname, 'out');

// 需要复制的单个文件
const FILES = [
  'index.html',
  'exam.html',
  'login.html',
  'admin.html',
  'style.css',
  'auth.css',
  'exam.css',
  'home.js',
  'exam.js',
  'CNAME',
];

// 需要整体复制的目录
const DIRS = ['images', 'video'];

// ——— 工具函数 ———

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function copyFile(src, dest) {
  if (!fs.existsSync(src)) return;
  ensureDir(path.dirname(dest));
  fs.copyFileSync(src, dest);
}

function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  ensureDir(dest);
  for (const entry of fs.readdirSync(src)) {
    const srcPath = path.join(src, entry);
    const destPath = path.join(dest, entry);
    if (fs.statSync(srcPath).isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// ——— 主流程 ———

ensureDir(OUT_DIR);

FILES.forEach(file => {
  copyFile(path.join(__dirname, file), path.join(OUT_DIR, file));
});

DIRS.forEach(dir => {
  copyDir(path.join(__dirname, dir), path.join(OUT_DIR, dir));
});

console.log('✅ 构建完成！静态文件已导出到 /out 目录。');
console.log('   用浏览器直接打开 out/index.html 即可访问。');
