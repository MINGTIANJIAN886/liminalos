/*!
 * Liminal 灵眸 · 鉴权与权限
 * ---------------------------------------------------------------------------
 * 密码派生参数与前端 account-store.js 保持一致（PBKDF2-SHA256 / 150000 次 /
 * 16 字节盐 / 256 位摘要），因此浏览器本地账号的凭据可以原样迁移入库，
 * 无需用户重置密码。
 * ---------------------------------------------------------------------------
 */
"use strict";

const crypto = require("node:crypto");
const { stmt, nowISO } = require("./db");

const PBKDF2_ITERATIONS = 150000;
const KEY_LENGTH = 32;
const DIGEST = "sha256";

const SESSION_TTL_DEFAULT = 8 * 60 * 60 * 1000; // 8 小时
const SESSION_TTL_REMEMBER = 30 * 24 * 60 * 60 * 1000; // 30 天
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION = 15 * 60 * 1000;

/* =========================================================================
 * 领域常量（与前端 account-store.js 逐字对齐，避免前后端判定不一致）
 * =======================================================================*/

const ROLES = {
  guest: { id: "guest", label: "受邀访客", rank: 1, description: "查看公开摘要与本人账号信息" },
  member: { id: "member", label: "项目成员", rank: 2, description: "进入工作台模块，下发与调整任务" },
  admin: { id: "admin", label: "系统管理员", rank: 3, description: "管理账号角色、状态与登录凭据" }
};

const STATUS = {
  pending: { id: "pending", label: "待审核", tone: "amber", description: "已提交注册，等待团队确认需求", canLogin: false },
  active: { id: "active", label: "正常", tone: "green", description: "权限已开通，可正常登录", canLogin: true },
  suspended: { id: "suspended", label: "已暂停", tone: "amber", description: "权限被临时暂停，可联系管理员恢复", canLogin: false },
  disabled: { id: "disabled", label: "已停用", tone: "rose", description: "账号已停用，不再允许登录", canLogin: false }
};

const CAPABILITIES = {
  "workspace.summary": { label: "查看公开摘要", roles: ["guest", "member", "admin"] },
  "workspace.modules": { label: "查看工作台模块", roles: ["member", "admin"] },
  "workspace.tasks": { label: "下发与调整任务", roles: ["member", "admin"] },
  "account.profile.read": { label: "查看本人资料", roles: ["guest", "member", "admin"] },
  "account.profile.write": { label: "修改本人资料", roles: ["guest", "member", "admin"] },
  "account.security": { label: "修改本人密码", roles: ["guest", "member", "admin"] },
  "account.directory": { label: "查看账号列表", roles: ["admin"] },
  "account.manage": { label: "调整账号角色与状态", roles: ["admin"] }
};

const DIRECTIONS = [
  "轨道交通多系统智能协同",
  "无人交通协同",
  "交通基础设施智能运维",
  "园区综合安全与连续作业",
  "工作台与系统能力",
  "其他"
];

/* =========================================================================
 * 密码派生
 * =======================================================================*/

function derive(password, saltB64, iterations) {
  const salt = Buffer.from(saltB64, "base64");
  return crypto
    .pbkdf2Sync(String(password), salt, iterations, KEY_LENGTH, DIGEST)
    .toString("base64");
}

function createCredential(password) {
  const salt = crypto.randomBytes(16).toString("base64");
  return {
    algo: "pbkdf2-sha256",
    salt: salt,
    hash: derive(password, salt, PBKDF2_ITERATIONS),
    iterations: PBKDF2_ITERATIONS
  };
}

/** 定时安全比较，避免通过响应时间差推断摘要。 */
function verifyCredential(password, account) {
  if (!account || !account.pwd_hash) return false;
  const computed = derive(password, account.pwd_salt, account.pwd_iter || PBKDF2_ITERATIONS);
  const a = Buffer.from(computed, "base64");
  const b = Buffer.from(account.pwd_hash, "base64");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/* =========================================================================
 * 会话
 * =======================================================================*/

function createSession(accountId, remember, meta) {
  const token = crypto.randomBytes(32).toString("base64url");
  const ttl = remember ? SESSION_TTL_REMEMBER : SESSION_TTL_DEFAULT;
  const issuedAt = nowISO();
  const expiresAt = new Date(Date.now() + ttl).toISOString();

  stmt.insertSession.run(
    token,
    accountId,
    (meta && meta.userAgent) || null,
    (meta && meta.ip) || null,
    issuedAt,
    expiresAt
  );

  return { token: token, issuedAt: issuedAt, expiresAt: expiresAt, ttl: ttl };
}

/** 解析 token：校验存在性、过期时间、账号状态。返回 { account, session } 或 null。 */
function resolveSession(token) {
  if (!token) return null;

  const session = stmt.findSession.get(token);
  if (!session) return null;

  if (Date.parse(session.expires_at) <= Date.now()) {
    stmt.deleteSession.run(token);
    return null;
  }

  const account = stmt.findById.get(session.account_id);
  if (!account || !STATUS[account.status] || !STATUS[account.status].canLogin) {
    stmt.deleteSessionsOf.run(session.account_id);
    return null;
  }

  return { account: account, session: session };
}

function destroySession(token) {
  if (token) stmt.deleteSession.run(token);
}

function purgeExpiredSessions() {
  const removed = stmt.purgeExpired.run(nowISO());
  return removed.changes;
}

/* =========================================================================
 * 权限
 * =======================================================================*/

function capabilitiesOf(account) {
  if (!account || !ROLES[account.role]) return [];
  return Object.keys(CAPABILITIES).filter(function (key) {
    return CAPABILITIES[key].roles.indexOf(account.role) !== -1;
  });
}

function can(account, capability) {
  if (!account) return false;
  const rule = CAPABILITIES[capability];
  if (!rule) return false;
  return rule.roles.indexOf(account.role) !== -1;
}

/* =========================================================================
 * 对外脱敏视图
 * =======================================================================*/

/** 绝不下发 pwd_* 字段。 */
function toPublic(account) {
  if (!account) return null;
  const status = STATUS[account.status] || { label: account.status, tone: "muted", canLogin: false };
  const role = ROLES[account.role] || { label: account.role };

  return {
    id: account.id,
    login: account.login,
    email: account.email,
    name: account.name,
    unit: account.unit,
    phone: account.phone,
    direction: account.direction,
    note: account.note,
    role: account.role,
    roleLabel: role.label,
    status: account.status,
    statusLabel: status.label,
    statusTone: status.tone,
    canLogin: Boolean(status.canLogin),
    credentialAlgo: account.pwd_algo,
    security: {
      failedAttempts: account.failed_attempts,
      lockedUntil: account.locked_until,
      lastLoginAt: account.last_login_at,
      loginCount: account.login_count
    },
    createdAt: account.created_at,
    updatedAt: account.updated_at,
    capabilities: capabilitiesOf(account)
  };
}

/* =========================================================================
 * 审计
 * =======================================================================*/

function audit(action, accountId, actorId, detail) {
  stmt.insertAudit.run(nowISO(), action, accountId || null, actorId || null, detail || null);
}

/* =========================================================================
 * 校验（与前端同规则）
 * =======================================================================*/

const normalizeLogin = (v) => String(v || "").trim().toLowerCase();
const isValidLogin = (v) => /^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalizeLogin(v));
const isValidEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(v || "").trim());

function passwordIssues(value) {
  const text = String(value || "");
  const issues = [];
  if (text.length < 8) issues.push("至少 8 位字符");
  if (!/[A-Za-z]/.test(text)) issues.push("包含字母");
  if (!/\d/.test(text)) issues.push("包含数字");
  return issues;
}

module.exports = {
  PBKDF2_ITERATIONS,
  SESSION_TTL_DEFAULT,
  SESSION_TTL_REMEMBER,
  MAX_FAILED_ATTEMPTS,
  LOCK_DURATION,
  ROLES,
  STATUS,
  CAPABILITIES,
  DIRECTIONS,
  createCredential,
  verifyCredential,
  createSession,
  resolveSession,
  destroySession,
  purgeExpiredSessions,
  capabilitiesOf,
  can,
  toPublic,
  audit,
  normalizeLogin,
  isValidLogin,
  isValidEmail,
  passwordIssues
};
