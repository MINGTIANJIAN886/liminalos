/*!
 * Liminal 灵眸 · 数据库层
 * ---------------------------------------------------------------------------
 * 使用 Node 24 内置的 node:sqlite，零 npm 依赖。
 *
 * 数据库文件位置：server/data/liminal.db（可用环境变量 LIMINAL_DB 覆盖）
 * 表结构：
 *   accounts    账号主表（含密码派生凭据、状态、安全计数）
 *   sessions    会话表（HttpOnly Cookie 中的 token 对应此处记录）
 *   audit_logs  审计表（注册、登录、状态变更等操作轨迹）
 * ---------------------------------------------------------------------------
 */
"use strict";

const { DatabaseSync } = require("node:sqlite");
const path = require("node:path");
const fs = require("node:fs");

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = process.env.LIMINAL_DB || path.join(DATA_DIR, "liminal.db");

if (!fs.existsSync(path.dirname(DB_FILE))) {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
}

const db = new DatabaseSync(DB_FILE);

// WAL 提升并发读性能；外键约束保证会话随账号级联删除。
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");
db.exec("PRAGMA busy_timeout = 5000;");

/* =========================================================================
 * 表结构
 * =======================================================================*/

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id              TEXT    PRIMARY KEY,
    login           TEXT    NOT NULL COLLATE NOCASE,
    email           TEXT    NOT NULL COLLATE NOCASE,
    name            TEXT    NOT NULL,
    unit            TEXT    NOT NULL DEFAULT '',
    phone           TEXT    NOT NULL DEFAULT '',
    direction       TEXT    NOT NULL DEFAULT '',
    note            TEXT    NOT NULL DEFAULT '',

    -- 角色与状态：用 CHECK 把领域约束下沉到数据库，避免脏数据。
    role            TEXT    NOT NULL DEFAULT 'guest'
                            CHECK (role IN ('guest','member','admin')),
    status          TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending','active','suspended','disabled')),

    -- 密码凭据：只存派生结果，永不存明文。
    pwd_algo        TEXT    NOT NULL,
    pwd_salt        TEXT    NOT NULL,
    pwd_hash        TEXT    NOT NULL,
    pwd_iter        INTEGER NOT NULL,

    -- 登录保护
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    last_login_at   TEXT,
    login_count     INTEGER NOT NULL DEFAULT 0,

    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
  );

  CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_login ON accounts (login COLLATE NOCASE);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email ON accounts (email COLLATE NOCASE);
  CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts (status);
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_agent TEXT,
    ip         TEXT,
    issued_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions (account_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    action     TEXT NOT NULL,
    account_id TEXT,
    actor_id   TEXT,
    detail     TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_logs (account_id, at DESC);
`);

/* =========================================================================
 * 语句缓存
 * =======================================================================*/

const stmt = {
  /* --- accounts --- */
  insertAccount: db.prepare(`
    INSERT INTO accounts (
      id, login, email, name, unit, phone, direction, note,
      role, status, pwd_algo, pwd_salt, pwd_hash, pwd_iter,
      failed_attempts, locked_until, last_login_at, login_count,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, 0, ?, ?)
  `),
  findById: db.prepare(`SELECT * FROM accounts WHERE id = ?`),
  findByLogin: db.prepare(`SELECT * FROM accounts WHERE login = ? COLLATE NOCASE`),
  findByEmail: db.prepare(`SELECT * FROM accounts WHERE email = ? COLLATE NOCASE`),
  findByLoginOrEmail: db.prepare(`
    SELECT * FROM accounts WHERE login = ? COLLATE NOCASE OR email = ? COLLATE NOCASE LIMIT 1
  `),
  listAccounts: db.prepare(`SELECT * FROM accounts ORDER BY created_at ASC`),
  countAccounts: db.prepare(`SELECT COUNT(*) AS n FROM accounts`),
  updateSecurity: db.prepare(`
    UPDATE accounts SET failed_attempts = ?, locked_until = ?, last_login_at = ?, login_count = ?, updated_at = ?
    WHERE id = ?
  `),
  updateCredential: db.prepare(`
    UPDATE accounts SET pwd_algo = ?, pwd_salt = ?, pwd_hash = ?, pwd_iter = ?,
      failed_attempts = 0, locked_until = NULL, updated_at = ?
    WHERE id = ?
  `),
  updateProfile: db.prepare(`
    UPDATE accounts SET email = ?, name = ?, unit = ?, phone = ?, direction = ?, note = ?, updated_at = ?
    WHERE id = ?
  `),
  updateRole: db.prepare(`UPDATE accounts SET role = ?, updated_at = ? WHERE id = ?`),
  updateStatus: db.prepare(`UPDATE accounts SET status = ?, updated_at = ? WHERE id = ?`),
  deleteAccount: db.prepare(`DELETE FROM accounts WHERE id = ?`),

  /* --- sessions --- */
  insertSession: db.prepare(`
    INSERT INTO sessions (token, account_id, user_agent, ip, issued_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
  findSession: db.prepare(`SELECT * FROM sessions WHERE token = ?`),
  deleteSession: db.prepare(`DELETE FROM sessions WHERE token = ?`),
  deleteSessionsOf: db.prepare(`DELETE FROM sessions WHERE account_id = ?`),
  purgeExpired: db.prepare(`DELETE FROM sessions WHERE expires_at <= ?`),

  /* --- audit --- */
  insertAudit: db.prepare(`
    INSERT INTO audit_logs (at, action, account_id, actor_id, detail) VALUES (?, ?, ?, ?, ?)
  `),
  listAudit: db.prepare(`
    SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?
  `),
  listAuditOf: db.prepare(`
    SELECT * FROM audit_logs WHERE account_id = ? OR actor_id = ? ORDER BY id DESC LIMIT ?
  `)
};

/* =========================================================================
 * 事务辅助
 *   node:sqlite 没有内置事务包装，手动 BEGIN / COMMIT / ROLLBACK。
 * =======================================================================*/

function transaction(fn) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    try {
      db.exec("ROLLBACK");
    } catch (rollbackError) {
      console.error("[db] 回滚失败：", rollbackError.message);
    }
    throw error;
  }
}

const nowISO = () => new Date().toISOString();

/** 判断错误是否为唯一约束冲突（用于把 DB 错误翻译成业务错误码）。 */
function isUniqueViolation(error, column) {
  if (!error || typeof error.message !== "string") return false;
  if (!/UNIQUE constraint failed/i.test(error.message)) return false;
  return column ? error.message.includes("accounts." + column) : true;
}

module.exports = {
  db,
  stmt,
  transaction,
  nowISO,
  isUniqueViolation,
  DB_FILE,
  file: DB_FILE
};
