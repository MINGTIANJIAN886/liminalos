/*!
 * Liminal 灵眸 · REST API 路由
 * ---------------------------------------------------------------------------
 * 统一响应体与前端 account-store.js 完全一致：
 *   { ok: boolean, code: string, message: string, data: any }
 * 这样前端只需把 driver 换成 HttpDriver，页面层的判断逻辑一行都不用改。
 *
 * 安全约定：
 *   1. 会话 token 走 HttpOnly + SameSite=Lax Cookie，JS 读不到，规避 XSS 窃取。
 *   2. 所有状态变更请求校验 Origin，配合 SameSite 防 CSRF。
 *   3. 权限在服务端二次校验——前端隐藏按钮不算数。
 *   4. 全部 SQL 走 prepared statement 参数绑定。
 *   5. 登录失败文案统一，不区分"账号不存在"与"密码错误"。
 * ---------------------------------------------------------------------------
 */
"use strict";

const crypto = require("node:crypto");
const db = require("./db");
const auth = require("./auth");

const COOKIE_NAME = "liminal_session";
const MAX_BODY_BYTES = 64 * 1024;

// 导入凭据缺失时使用的兜底口令（仅用于本地迁移，正式账号应带哈希导入）。
const FALLBACK_PASSWORD = "Liminal@2026";

const ok = (code, message, data) => ({ status: 200, body: { ok: true, code: code, message: message, data: data === undefined ? null : data } });
const fail = (status, code, message) => ({ status: status, body: { ok: false, code: code, message: message, data: null } });

const newId = () => "acc_" + crypto.randomBytes(12).toString("hex");

/* =========================================================================
 * 请求上下文辅助
 * =======================================================================*/

function parseCookies(header) {
  const jar = {};
  if (!header) return jar;
  header.split(";").forEach(function (part) {
    const index = part.indexOf("=");
    if (index < 0) return;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) jar[key] = decodeURIComponent(value);
  });
  return jar;
}

function readBody(req) {
  return new Promise(function (resolve, reject) {
    let size = 0;
    const chunks = [];
    req.on("data", function (chunk) {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("请求体过大"), { code: "payload_too_large" }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", function () {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(Object.assign(new Error("请求体不是合法 JSON"), { code: "bad_json" }));
      }
    });
    req.on("error", reject);
  });
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // 同源 fetch 在部分场景不带 Origin，交给 SameSite 兜底
  const host = req.headers.host;
  try {
    return new URL(origin).host === host;
  } catch (error) {
    return false;
  }
}

function setSessionCookie(res, token, expiresAt, secure) {
  const maxAge = Math.max(0, Math.floor((Date.parse(expiresAt) - Date.now()) / 1000));
  const parts = [
    COOKIE_NAME + "=" + encodeURIComponent(token),
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=" + maxAge
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", COOKIE_NAME + "=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
}

/* =========================================================================
 * 业务处理
 * =======================================================================*/

async function register(ctx) {
  const body = ctx.body || {};
  const login = auth.normalizeLogin(body.login);
  const email = String(body.email || "").trim();
  const name = String(body.name || "").trim();
  const unit = String(body.unit || "").trim();

  if (!auth.isValidLogin(login)) return fail(400, "login_invalid", "账号需为 3-32 位小写字母、数字或 . _ -，且以字母或数字开头。");
  if (!auth.isValidEmail(email)) return fail(400, "email_invalid", "请填写有效的邮箱地址。");
  if (!name) return fail(400, "name_required", "请填写姓名。");
  if (!unit) return fail(400, "unit_required", "请填写单位或学校。");

  const issues = auth.passwordIssues(body.password);
  if (issues.length) return fail(400, "password_weak", "密码需" + issues.join("、") + "。");
  if (String(body.password) !== String(body.confirm)) return fail(400, "password_mismatch", "两次输入的密码不一致。");

  if (db.stmt.findByLogin.get(login)) return fail(409, "login_taken", "该账号已被注册。");
  if (db.stmt.findByEmail.get(email)) return fail(409, "email_taken", "该邮箱已被注册。");

  const role = auth.ROLES[body.role] ? body.role : "guest";
  const direction = auth.DIRECTIONS.indexOf(body.direction) !== -1 ? body.direction : "其他";
  const credential = auth.createCredential(body.password);
  const now = db.nowISO();
  const id = newId();

  try {
    db.stmt.insertAccount.run(
      id, login, email, name, unit,
      String(body.phone || "").trim(), direction,
      String(body.note || "").trim(), role,
      "pending", // 自助注册一律待审核
      credential.algo, credential.salt, credential.hash, credential.iterations,
      now, now
    );
  } catch (error) {
    if (db.isUniqueViolation(error, "login")) return fail(409, "login_taken", "该账号已被注册。");
    if (db.isUniqueViolation(error, "email")) return fail(409, "email_taken", "该邮箱已被注册。");
    throw error;
  }

  const account = db.stmt.findById.get(id);
  auth.audit("register", id, null, "注册账号 " + login + "，角色 " + role);
  return ok("registered", "注册申请已提交，审核通过后即可登录。", auth.toPublic(account));
}

async function login(ctx) {
  const body = ctx.body || {};
  const identifier = String(body.login || "").trim();
  const password = String(body.password || "");

  if (!identifier || !password) return fail(400, "empty", "请输入账号与访问密码。");

  const account = db.stmt.findByLoginOrEmail.get(identifier, identifier);
  if (!account) {
    // 与"密码错误"返回同一文案同一状态码，避免账号枚举。
    auth.audit("login_failed", null, null, "账号不存在：" + identifier);
    return fail(401, "credential_invalid", "账号或访问密码不正确。");
  }

  if (account.locked_until && Date.parse(account.locked_until) > Date.now()) {
    const minutes = Math.ceil((Date.parse(account.locked_until) - Date.now()) / 60000);
    return fail(423, "locked", "登录失败次数过多，账号已锁定，请 " + minutes + " 分钟后重试。");
  }

  if (!auth.verifyCredential(password, account)) {
    const attempts = account.failed_attempts + 1;
    let lockedUntil = null;
    if (attempts >= auth.MAX_FAILED_ATTEMPTS) {
      lockedUntil = new Date(Date.now() + auth.LOCK_DURATION).toISOString();
    }
    db.stmt.updateSecurity.run(
      lockedUntil ? 0 : attempts,
      lockedUntil,
      account.last_login_at,
      account.login_count,
      db.nowISO(),
      account.id
    );
    auth.audit(lockedUntil ? "lock" : "login_failed", account.id, null,
      lockedUntil ? "连续登录失败达到上限，账号锁定" : "密码校验失败，累计 " + attempts + " 次");
    if (lockedUntil) return fail(423, "locked", "登录失败次数过多，账号已锁定 15 分钟。");
    return fail(401, "credential_invalid", "账号或访问密码不正确。");
  }

  const status = auth.STATUS[account.status];
  if (!status || !status.canLogin) {
    auth.audit("login_blocked", account.id, null, "账号状态为 " + account.status + "，拒绝建立会话");
    return fail(403, "status_" + account.status,
      "该账号当前状态为「" + status.label + "」，" + status.description + "。");
  }

  const session = auth.createSession(account.id, Boolean(body.remember), {
    userAgent: ctx.userAgent,
    ip: ctx.ip
  });

  db.stmt.updateSecurity.run(0, null, db.nowISO(), account.login_count + 1, db.nowISO(), account.id);

  const fresh = db.stmt.findById.get(account.id);
  auth.audit("login", account.id, account.id, "登录成功，会话至 " + session.expiresAt);
  setSessionCookie(ctx.res, session.token, session.expiresAt, ctx.secure);

  return ok("logged_in", "登录成功。", {
    user: auth.toPublic(fresh),
    session: { issuedAt: session.issuedAt, expiresAt: session.expiresAt }
  });
}

async function logout(ctx) {
  if (ctx.account) auth.audit("logout", ctx.account.id, ctx.account.id, "主动退出登录");
  auth.destroySession(ctx.token);
  clearSessionCookie(ctx.res);
  return ok("logged_out", "已退出登录。");
}

async function session(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "当前没有有效会话。");
  return ok("session", "会话有效。", {
    user: auth.toPublic(ctx.account),
    session: { expiresAt: ctx.session.expires_at }
  });
}

async function updateProfile(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "登录状态已失效，请重新登录。");
  if (!auth.can(ctx.account, "account.profile.write")) return fail(403, "forbidden", "当前账号无权修改资料。");

  const body = ctx.body || {};
  const email = body.email === undefined ? ctx.account.email : String(body.email).trim();
  const name = body.name === undefined ? ctx.account.name : String(body.name).trim();
  const unit = body.unit === undefined ? ctx.account.unit : String(body.unit).trim();
  const phone = body.phone === undefined ? ctx.account.phone : String(body.phone).trim();
  const note = body.note === undefined ? ctx.account.note : String(body.note).trim();
  const direction = auth.DIRECTIONS.indexOf(body.direction) !== -1 ? body.direction : ctx.account.direction;

  if (!auth.isValidEmail(email)) return fail(400, "email_invalid", "请填写有效的邮箱地址。");
  if (!name) return fail(400, "name_required", "姓名不能为空。");
  if (!unit) return fail(400, "unit_required", "单位或学校不能为空。");

  const conflict = db.stmt.findByEmail.get(email);
  if (conflict && conflict.id !== ctx.account.id) return fail(409, "email_taken", "该邮箱已被其他账号使用。");

  db.stmt.updateProfile.run(email, name, unit, phone, direction, note, db.nowISO(), ctx.account.id);

  const fresh = db.stmt.findById.get(ctx.account.id);
  auth.audit("profile_update", ctx.account.id, ctx.account.id, "更新个人资料");
  return ok("profile_updated", "资料已保存。", auth.toPublic(fresh));
}

async function changePassword(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "登录状态已失效，请重新登录。");
  if (!auth.can(ctx.account, "account.security")) return fail(403, "forbidden", "当前账号无权修改密码。");

  const body = ctx.body || {};
  if (!auth.verifyCredential(String(body.current || ""), ctx.account)) {
    return fail(400, "current_invalid", "当前访问密码不正确。");
  }

  const issues = auth.passwordIssues(body.next);
  if (issues.length) return fail(400, "password_weak", "新密码需" + issues.join("、") + "。");
  if (String(body.next) !== String(body.confirm)) return fail(400, "password_mismatch", "两次输入的新密码不一致。");
  if (String(body.next) === String(body.current)) return fail(400, "password_same", "新密码不能与当前密码相同。");

  const credential = auth.createCredential(body.next);
  db.stmt.updateCredential.run(credential.algo, credential.salt, credential.hash, credential.iterations, db.nowISO(), ctx.account.id);

  // 改密后注销该账号的全部会话，再为当前设备建立新会话，旧票据立即失效。
  db.stmt.deleteSessionsOf.run(ctx.account.id);
  const session = auth.createSession(ctx.account.id, true, { userAgent: ctx.userAgent, ip: ctx.ip });
  setSessionCookie(ctx.res, session.token, session.expiresAt, ctx.secure);

  const fresh = db.stmt.findById.get(ctx.account.id);
  auth.audit("password_change", ctx.account.id, ctx.account.id, "修改访问密码并注销其他会话");
  return ok("password_changed", "访问密码已更新，其他设备需重新登录。", auth.toPublic(fresh));
}

async function listAccounts(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "登录状态已失效，请重新登录。");
  if (!auth.can(ctx.account, "account.directory")) return fail(403, "forbidden", "当前账号无权查看账号列表。");

  const rows = db.stmt.listAccounts.all().map(function (row) {
    const view = auth.toPublic(row);
    view.isSelf = row.id === ctx.account.id;
    return view;
  });

  const rank = (row) => (auth.ROLES[row.role] ? auth.ROLES[row.role].rank : 0);
  rows.sort((a, b) => rank(b) - rank(a) || String(a.createdAt).localeCompare(String(b.createdAt)));

  return ok("listed", "已加载 " + rows.length + " 个账号。", rows);
}

async function setStatus(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "登录状态已失效，请重新登录。");
  if (!auth.can(ctx.account, "account.manage")) return fail(403, "forbidden", "当前账号无权调整账号状态。");

  const status = String((ctx.body || {}).status || "");
  if (!auth.STATUS[status]) return fail(400, "status_unknown", "未知的账号状态。");
  if (ctx.params.id === ctx.account.id) return fail(400, "self_forbidden", "不能调整本人账号的状态。");

  const target = db.stmt.findById.get(ctx.params.id);
  if (!target) return fail(404, "not_found", "账号不存在。");

  db.stmt.updateStatus.run(status, db.nowISO(), target.id);
  // 状态变为不可登录时，立即清除该账号的全部会话。
  if (!auth.STATUS[status].canLogin) db.stmt.deleteSessionsOf.run(target.id);

  const fresh = db.stmt.findById.get(target.id);
  auth.audit("status_change", target.id, ctx.account.id, "状态调整为 " + auth.STATUS[status].label);
  return ok("status_updated", target.name + " 的状态已调整为「" + auth.STATUS[status].label + "」。", auth.toPublic(fresh));
}

async function setRole(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "登录状态已失效，请重新登录。");
  if (!auth.can(ctx.account, "account.manage")) return fail(403, "forbidden", "当前账号无权调整账号角色。");

  const role = String((ctx.body || {}).role || "");
  if (!auth.ROLES[role]) return fail(400, "role_unknown", "未知的角色。");
  if (ctx.params.id === ctx.account.id) return fail(400, "self_forbidden", "不能调整本人的角色。");

  const target = db.stmt.findById.get(ctx.params.id);
  if (!target) return fail(404, "not_found", "账号不存在。");

  db.stmt.updateRole.run(role, db.nowISO(), target.id);
  const fresh = db.stmt.findById.get(target.id);
  auth.audit("role_change", target.id, ctx.account.id, "角色调整为 " + auth.ROLES[role].label);
  return ok("role_updated", target.name + " 的角色已调整为「" + auth.ROLES[role].label + "」。", auth.toPublic(fresh));
}

async function resetPassword(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "登录状态已失效，请重新登录。");
  if (!auth.can(ctx.account, "account.manage")) return fail(403, "forbidden", "当前账号无权重置密码。");

  const next = String((ctx.body || {}).password || "");
  const issues = auth.passwordIssues(next);
  if (issues.length) return fail(400, "password_weak", "临时密码需" + issues.join("、") + "。");

  const target = db.stmt.findById.get(ctx.params.id);
  if (!target) return fail(404, "not_found", "账号不存在。");

  const credential = auth.createCredential(next);
  db.stmt.updateCredential.run(credential.algo, credential.salt, credential.hash, credential.iterations, db.nowISO(), target.id);
  db.stmt.deleteSessionsOf.run(target.id);

  auth.audit("password_reset", target.id, ctx.account.id, "由管理员重置访问密码");
  const fresh = db.stmt.findById.get(target.id);
  return ok("password_reset", "已为 " + target.name + " 重置访问密码。", auth.toPublic(fresh));
}

async function auditLog(ctx) {
  if (!ctx.account) return fail(401, "unauthenticated", "登录状态已失效，请重新登录。");
  const isAdmin = auth.can(ctx.account, "account.directory");
  const limit = Math.min(Math.max(Number((ctx.query.get("limit") || 20)), 1), 200);

  const rows = isAdmin
    ? db.stmt.listAudit.all(limit)
    : db.stmt.listAuditOf.all(ctx.account.id, ctx.account.id, limit);

  return ok("listed", "已加载 " + rows.length + " 条记录。", rows.map(function (row) {
    return {
      id: row.id,
      at: row.at,
      action: row.action,
      accountId: row.account_id,
      actorId: row.actor_id,
      detail: row.detail
    };
  }));
}

/** 元数据：把角色、状态、能力矩阵下发给前端，避免前后端硬编码漂移。 */
async function metadata() {
  return ok("metadata", "已加载领域元数据。", {
    roles: auth.ROLES,
    status: auth.STATUS,
    capabilities: auth.CAPABILITIES,
    directions: auth.DIRECTIONS,
    policy: {
      pbkdf2Iterations: auth.PBKDF2_ITERATIONS,
      maxFailedAttempts: auth.MAX_FAILED_ATTEMPTS,
      lockDuration: auth.LOCK_DURATION,
      sessionTtlDefault: auth.SESSION_TTL_DEFAULT,
      sessionTtlRemember: auth.SESSION_TTL_REMEMBER
    }
  });
}

/* =========================================================================
 * 导入：把浏览器 localStorage 里的账号迁入数据库
 *   仅当数据库为空时开放，且必须提供一次性令牌（服务端启动时打印到控制台）。
 * =======================================================================*/

async function importLocal(ctx) {
  if (db.stmt.countAccounts.get().n > 0) {
    return fail(409, "not_empty", "数据库已有账号，导入通道已关闭。");
  }
  if (!ctx.server.importToken || String((ctx.body || {}).token || "") !== ctx.server.importToken) {
    return fail(403, "bad_token", "导入令牌不正确，请查看服务端控制台输出。");
  }

  const accounts = Array.isArray((ctx.body || {}).accounts) ? ctx.body.accounts : [];
  if (!accounts.length) return fail(400, "empty_payload", "没有可导入的账号。");

  const inserted = [];
  const skipped = [];

  db.transaction(function () {
    accounts.forEach(function (raw) {
      const login = auth.normalizeLogin(raw.login);
      if (!auth.isValidLogin(login) || db.stmt.findByLogin.get(login)) {
        skipped.push(login || "(无效账号)");
        return;
      }
      const credential = raw.password && raw.password.hash
        ? {
            algo: raw.password.algo || "pbkdf2-sha256",
            salt: raw.password.salt,
            hash: raw.password.hash,
            iterations: raw.password.iterations || auth.PBKDF2_ITERATIONS
          }
        : auth.createCredential(FALLBACK_PASSWORD);

      const now = db.nowISO();
      const id = newId();
      const security = raw.security || {};

      db.stmt.insertAccount.run(
        id, login, String(raw.email || login + "@liminal.local"), String(raw.name || login),
        String(raw.unit || ""), String(raw.phone || ""),
        auth.DIRECTIONS.indexOf(raw.direction) !== -1 ? raw.direction : "其他",
        String(raw.note || ""), auth.ROLES[raw.role] ? raw.role : "guest",
        auth.STATUS[raw.status] ? raw.status : "pending",
        credential.algo, credential.salt, credential.hash, credential.iterations,
        raw.createdAt || now, now
      );

      if (security.loginCount || security.lastLoginAt || security.failedAttempts || security.lockedUntil) {
        db.stmt.updateSecurity.run(
          security.failedAttempts || 0,
          security.lockedUntil || null,
          security.lastLoginAt || null,
          security.loginCount || 0,
          now,
          id
        );
      }

      inserted.push(login);
    });
  });

  auth.audit("import", null, null, "从浏览器导入 " + inserted.length + " 个账号");
  return ok("imported", "已导入 " + inserted.length + " 个账号" + (skipped.length ? "，跳过 " + skipped.length + " 个重复或无效账号。" : "。"), {
    inserted: inserted,
    skipped: skipped
  });
}

/* =========================================================================
 * 路由表
 * =======================================================================*/

const ROUTES = [
  { method: "GET", pattern: /^\/api\/health$/, handler: async () => ok("healthy", "服务正常。", { time: db.nowISO(), storage: "sqlite" }) },
  { method: "GET", pattern: /^\/api\/metadata$/, handler: metadata },

  { method: "POST", pattern: /^\/api\/auth\/register$/, handler: register },
  { method: "POST", pattern: /^\/api\/auth\/login$/, handler: login },
  { method: "POST", pattern: /^\/api\/auth\/logout$/, handler: logout },
  { method: "GET", pattern: /^\/api\/auth\/session$/, handler: session },

  { method: "PATCH", pattern: /^\/api\/account\/profile$/, handler: updateProfile },
  { method: "POST", pattern: /^\/api\/account\/password$/, handler: changePassword },
  { method: "GET", pattern: /^\/api\/account\/audit$/, handler: auditLog },

  { method: "GET", pattern: /^\/api\/admin\/accounts$/, handler: listAccounts },
  { method: "PATCH", pattern: /^\/api\/admin\/accounts\/([^/]+)\/status$/, handler: setStatus, param: "id" },
  { method: "PATCH", pattern: /^\/api\/admin\/accounts\/([^/]+)\/role$/, handler: setRole, param: "id" },
  { method: "POST", pattern: /^\/api\/admin\/accounts\/([^/]+)\/password$/, handler: resetPassword, param: "id" },

  { method: "POST", pattern: /^\/api\/setup\/import$/, handler: importLocal }
];

const MUTATING = new Set(["POST", "PATCH", "PUT", "DELETE"]);

/**
 * 处理一个 API 请求。
 * @returns {Promise<boolean>} 是否已处理（false 表示不是 API 路由，交给静态托管）
 */
async function handle(req, res, server) {
  const url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  if (!url.pathname.startsWith("/api/")) return false;

  const jar = parseCookies(req.headers.cookie);
  const token = jar[COOKIE_NAME] || null;
  const resolved = auth.resolveSession(token);

  const ctx = {
    res: res,
    server: server,
    query: url.searchParams,
    params: {},
    body: {},
    token: token,
    ip: req.socket.remoteAddress,
    userAgent: req.headers["user-agent"],
    secure: Boolean(server.secure),
    account: resolved ? resolved.account : null,
    session: resolved ? resolved.session : null
  };

  // CSRF：状态变更请求必须来自同源。
  if (MUTATING.has(req.method) && !sameOrigin(req)) {
    return respond(res, fail(403, "cross_origin", "请求来源不被允许。"));
  }

  if (MUTATING.has(req.method)) {
    try {
      ctx.body = await readBody(req);
    } catch (error) {
      const status = error.code === "payload_too_large" ? 413 : 400;
      return respond(res, fail(status, error.code || "bad_request", error.message));
    }
  }

  for (const route of ROUTES) {
    if (route.method !== req.method) continue;
    const match = route.pattern.exec(url.pathname);
    if (!match) continue;
    if (route.param) ctx.params[route.param] = decodeURIComponent(match[1]);

    try {
      const result = await route.handler(ctx);
      return respond(res, result);
    } catch (error) {
      console.error("[api] " + req.method + " " + url.pathname + " 失败：", error);
      return respond(res, fail(500, "server_error", "服务端处理失败，请稍后重试。"));
    }
  }

  return respond(res, fail(404, "not_found", "接口不存在。"));
}

function respond(res, result) {
  const payload = JSON.stringify(result.body);
  res.writeHead(result.status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store"
  });
  res.end(payload);
  return true;
}

module.exports = { handle, COOKIE_NAME, ROUTES };
