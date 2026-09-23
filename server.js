/*!
 * Liminal 灵眸 · 应用服务
 * ---------------------------------------------------------------------------
 * 一个进程同时做两件事：
 *   1. 托管静态站点（HTML/CSS/JS/媒体资源）
 *   2. 提供 /api/* REST 接口，账号数据落 SQLite
 *
 * 零 npm 依赖：只使用 Node 24 内置的 node:http / node:sqlite / node:crypto。
 *
 * 启动：  node server.js
 * 端口：  LIMINAL_PORT  （默认 8080）
 * 数据库：LIMINAL_DB    （默认 server/data/liminal.db）
 * 跳过播种：LIMINAL_SKIP_SEED=1
 * ---------------------------------------------------------------------------
 */
"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const db = require("./server/db");
const routes = require("./server/routes");
const { seedIfEmpty, SEED_PASSWORD } = require("./server/seed");
const auth = require("./server/auth");

const PORT = Number(process.env.LIMINAL_PORT || 8080);
const HOST = process.env.LIMINAL_HOST || "0.0.0.0";
const STATIC_ROOT = __dirname;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

/* =========================================================================
 * 静态资源
 * =======================================================================*/

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf"
};

/** 这些路径永不通过静态托管暴露（后端源码 + SQLite 数据库）。 */
const BLOCKED_PREFIXES = ["/server/", "/server", "/node_modules/"];

function sendFile(req, res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const type = MIME[ext] || "application/octet-stream";
  const size = fs.statSync(filePath).size;

  const headers = {
    "Content-Type": type,
    "Content-Length": size,
    // HTML 不缓存，媒体资源长缓存，避免改版后拿到旧页面。
    "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=604800"
  };
  headers["X-Content-Type-Options"] = "nosniff";

  // 静态资源支持 Range 请求，视频拖动进度条需要。
  const range = req.headers.range;
  if (range && /^bytes=\d*-\d*$/.test(range)) {
    const [startText, endText] = range.replace("bytes=", "").split("-");
    const start = startText ? Number(startText) : 0;
    const end = endText ? Number(endText) : size - 1;
    if (start >= size || end >= size || start > end) {
      res.writeHead(416, { "Content-Range": "bytes */" + size });
      res.end();
      return;
    }
    res.writeHead(206, Object.assign({}, headers, {
      "Content-Range": "bytes " + start + "-" + end + "/" + size,
      "Content-Length": end - start + 1,
      "Accept-Ranges": "bytes"
    }));
    fs.createReadStream(filePath, { start: start, end: end }).pipe(res);
    return;
  }

  headers["Accept-Ranges"] = "bytes";
  res.writeHead(200, headers);
  fs.createReadStream(filePath).pipe(res);
}

function serveStatic(req, res) {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://x").pathname);
  } catch (error) {
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("请求路径无法解析");
    return;
  }

  if (BLOCKED_PREFIXES.some((prefix) => pathname === prefix.replace(/\/$/, "") || pathname.startsWith(prefix))) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("404");
    return;
  }

  let target = path.normalize(path.join(STATIC_ROOT, pathname));

  // 目录穿越防护：解析后的路径必须仍在站点根目录内。
  if (!target.startsWith(STATIC_ROOT)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("403");
    return;
  }

  if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
    target = path.join(target, "index.html");
  }

  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
    const notFound = path.join(STATIC_ROOT, "404.html");
    if (fs.existsSync(notFound)) {
      res.writeHead(404, { "Content-Type": MIME[".html"] });
      fs.createReadStream(notFound).pipe(res);
      return;
    }
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("404 Not Found");
    return;
  }

  sendFile(req, res, target);
}

/* =========================================================================
 * 服务
 * =======================================================================*/

const server = {
  secure: IS_PRODUCTION, // 生产环境走 HTTPS 时给 Cookie 加 Secure
  importToken: crypto.randomBytes(16).toString("hex")
};

const app = http.createServer(function (req, res) {
  // 基础安全响应头
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "same-origin");

  routes.handle(req, res, server)
    .then(function (handled) {
      if (!handled) serveStatic(req, res);
    })
    .catch(function (error) {
      console.error("[server] 未捕获异常：", error);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("服务器内部错误");
      }
    });
});

/* =========================================================================
 * 启动
 * =======================================================================*/

const seedResult = seedIfEmpty();
const purged = auth.purgeExpiredSessions();

app.listen(PORT, HOST, function () {
  const line = "─".repeat(66);
  console.log("\n" + line);
  console.log("  Liminal 灵眸 · 服务已启动");
  console.log(line);
  console.log("  站点地址    http://localhost:" + PORT + "/index.html");
  console.log("  登录入口    http://localhost:" + PORT + "/login.html");
  console.log("  账号中心    http://localhost:" + PORT + "/account.html");
  console.log("  数据库      " + db.DB_FILE);
  console.log("  账号总数    " + db.stmt.countAccounts.get().n +
    (seedResult.seeded ? "（本次播种 " + seedResult.seeded + " 个演示账号）" : ""));
  if (purged) console.log("  清理会话    " + purged + " 条已过期");
  console.log(line);
  if (seedResult.seeded) {
    console.log("  演示账号    guest / member / admin / pending");
    console.log("  统一密码    " + SEED_PASSWORD);
    console.log(line);
  }
  console.log("  本地迁移令牌（仅数据库为空时可用于导入浏览器账号）");
  console.log("  " + server.importToken);
  console.log(line + "\n");
});

// 每 10 分钟清理过期会话
const purgeTimer = setInterval(function () {
  const removed = auth.purgeExpiredSessions();
  if (removed) console.log("[cleanup] 清理过期会话 " + removed + " 条");
}, 10 * 60 * 1000);
purgeTimer.unref();

function shutdown(signal) {
  console.log("\n[server] 收到 " + signal + "，正在关闭…");
  clearInterval(purgeTimer);
  app.close(function () {
    try {
      db.db.close();
    } catch (error) {
      /* 忽略关闭异常 */
    }
    console.log("[server] 已安全退出。");
    process.exit(0);
  });
  setTimeout(function () { process.exit(0); }, 3000).unref();
}

process.on("SIGINT", function () { shutdown("SIGINT"); });
process.on("SIGTERM", function () { shutdown("SIGTERM"); });
