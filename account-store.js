/*!
 * Liminal 灵眸 · 账号数据层
 * ---------------------------------------------------------------------------
 * 职责：账号数据的存放、结构、读写、鉴权、会话与权限判定的唯一入口。
 *
 * 存储位置
 *   演示态（当前）：浏览器 localStorage，命名空间 liminal.account.*
 *     - liminal.account.db.v1       账号库（schema + accounts[]）
 *     - liminal.account.session.v1  当前会话票据
 *     - liminal.account.audit.v1    审计日志（滚动保留最近 200 条）
 *   生产态（待接入）：后端数据库表 liminal_account / liminal_session，
 *     前端只需把 driver 换成 HttpDriver，本文件其余逻辑与校验规则可原样复用。
 *
 * 安全约定
 *   1. 密码永不明文落盘。使用 PBKDF2-SHA256（150000 次迭代 + 16 字节随机盐）
 *      派生 256 位摘要，仅保存 { algo, salt, hash, iterations }。
 *   2. 对外的账号对象一律经 toPublic() 脱敏，password 字段不出数据层。
 *   3. 前端本地哈希只能防止"明文裸奔"，无法抵御离线暴力破解；
 *      生产环境必须把哈希与校验迁移到服务端。
 * ---------------------------------------------------------------------------
 */
(function (global) {
  "use strict";

  /* =========================================================================
   * 1. 常量与领域模型
   * =======================================================================*/

  const SCHEMA_VERSION = 1;
  const NAMESPACE = "liminal.account";
  const KEYS = {
    db: NAMESPACE + ".db.v1",
    session: NAMESPACE + ".session.v1",
    audit: NAMESPACE + ".audit.v1"
  };

  const PBKDF2_ITERATIONS = 150000;
  const SESSION_TTL_DEFAULT = 8 * 60 * 60 * 1000; // 8 小时
  const SESSION_TTL_REMEMBER = 30 * 24 * 60 * 60 * 1000; // 30 天
  const AUDIT_LIMIT = 200;

  /**
   * 登录保护策略。本地模式用默认值；接入服务端后由 /api/metadata 下发的
   * policy 覆盖，保证前后端判定一致。
   */
  const runtimePolicy = {
    maxFailedAttempts: 5,
    lockDuration: 15 * 60 * 1000
  };

  /** 角色：rank 用于表达权限包含关系，数值越大权限越高。 */
  const ROLES = {
    guest: { id: "guest", label: "受邀访客", rank: 1, description: "查看公开摘要与本人账号信息" },
    member: { id: "member", label: "项目成员", rank: 2, description: "进入工作台模块，下发与调整任务" },
    admin: { id: "admin", label: "系统管理员", rank: 3, description: "管理账号角色、状态与登录凭据" }
  };

  /** 账号状态：决定能否建立会话。 */
  const STATUS = {
    pending: { id: "pending", label: "待审核", tone: "amber", description: "已提交注册，等待团队确认需求", canLogin: false },
    active: { id: "active", label: "正常", tone: "green", description: "权限已开通，可正常登录", canLogin: true },
    suspended: { id: "suspended", label: "已暂停", tone: "amber", description: "权限被临时暂停，可联系管理员恢复", canLogin: false },
    disabled: { id: "disabled", label: "已停用", tone: "rose", description: "账号已停用，不再允许登录", canLogin: false }
  };

  /** 能力矩阵：页面与操作按 capability 做门禁，而不是散落的角色判断。 */
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
   * 2. 存储驱动
   *    演示态使用 localStorage；接入后端时实现同名方法的 HttpDriver 即可。
   * =======================================================================*/

  const LocalDriver = {
    name: "localStorage",
    available: (function () {
      try {
        const probe = NAMESPACE + ".probe";
        global.localStorage.setItem(probe, "1");
        global.localStorage.removeItem(probe);
        return true;
      } catch (error) {
        return false;
      }
    })(),
    read: function (key, fallback) {
      if (!this.available) return fallback;
      try {
        const raw = global.localStorage.getItem(key);
        return raw === null ? fallback : JSON.parse(raw);
      } catch (error) {
        console.warn("[AccountStore] 读取失败，已回退默认值：", key, error);
        return fallback;
      }
    },
    write: function (key, value) {
      if (!this.available) return false;
      try {
        global.localStorage.setItem(key, JSON.stringify(value));
        return true;
      } catch (error) {
        console.warn("[AccountStore] 写入失败：", key, error);
        return false;
      }
    },
    remove: function (key) {
      if (!this.available) return;
      try {
        global.localStorage.removeItem(key);
      } catch (error) {
        console.warn("[AccountStore] 删除失败：", key, error);
      }
    }
  };

  const driver = LocalDriver;

  /* =========================================================================
   * 3. 基础工具
   * =======================================================================*/

  const ok = (code, message, data) => ({ ok: true, code: code, message: message, data: data === undefined ? null : data });
  const fail = (code, message) => ({ ok: false, code: code, message: message, data: null });

  const nowISO = () => new Date().toISOString();

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    if (global.crypto && typeof global.crypto.getRandomValues === "function") {
      global.crypto.getRandomValues(bytes);
    } else {
      for (let i = 0; i < length; i += 1) bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
  }

  function toBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return global.btoa(binary);
  }

  function fromBase64(text) {
    const binary = global.atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function randomToken(byteLength) {
    return toBase64(randomBytes(byteLength || 32)).replace(/[+/=]/g, "").slice(0, 43);
  }

  function makeId(prefix) {
    return prefix + "_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  function normalizeLogin(value) {
    return String(value || "").trim().toLowerCase();
  }

  function normalizePassword(value) {
    return String(value || "");
  }

  function isValidLogin(value) {
    return /^[a-z0-9][a-z0-9._-]{2,31}$/.test(normalizeLogin(value));
  }

  function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(value || "").trim());
  }

  function passwordIssues(value) {
    const text = normalizePassword(value);
    const issues = [];
    if (text.length < 8) issues.push("至少 8 位字符");
    if (!/[A-Za-z]/.test(text)) issues.push("包含字母");
    if (!/\d/.test(text)) issues.push("包含数字");
    return issues;
  }

  /** 轻量文本转义，供页面拼接 HTML 时使用。 */
  function escapeHTML(value) {
    return String(value === undefined || value === null ? "" : value).replace(/[&<>"']/g, function (char) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
    });
  }

  /* =========================================================================
   * 4. 密码派生
   * =======================================================================*/

  function fnv1a(text) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, "0");
  }

  /**
   * 生成凭据记录。PBKDF2 不可用时降级为不可逆弱摘要，
   * 以保证站点在非安全上下文（如部分 file:// 场景）仍可运行，
   * 此时凭据中的 algo 会标记为 insecure，页面据此给出提示。
   */
  async function createCredential(password) {
    const saltB64 = toBase64(randomBytes(16));
    const subtle = global.crypto && global.crypto.subtle;
    if (!subtle || typeof subtle.importKey !== "function") {
      return { algo: "fnv1a-insecure", salt: saltB64, hash: fnv1a(saltB64 + "|" + normalizePassword(password)), iterations: 0 };
    }
    const encoded = new TextEncoder().encode(normalizePassword(password));
    const keyMaterial = await subtle.importKey("raw", encoded, "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "PBKDF2", salt: fromBase64(saltB64), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      keyMaterial,
      256
    );
    return { algo: "pbkdf2-sha256", salt: saltB64, hash: toBase64(new Uint8Array(bits)), iterations: PBKDF2_ITERATIONS };
  }

  async function verifyCredential(password, credential) {
    if (!credential || !credential.hash) return false;
    if (credential.algo === "fnv1a-insecure") {
      return fnv1a(credential.salt + "|" + normalizePassword(password)) === credential.hash;
    }
    const subtle = global.crypto && global.crypto.subtle;
    if (!subtle) return false;
    const encoded = new TextEncoder().encode(normalizePassword(password));
    const keyMaterial = await subtle.importKey("raw", encoded, "PBKDF2", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: fromBase64(credential.salt),
        iterations: credential.iterations || PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    return toBase64(new Uint8Array(bits)) === credential.hash;
  }

  /* =========================================================================
   * 5. 账号库读写
   * =======================================================================*/

  function emptyDb() {
    return { schema: SCHEMA_VERSION, createdAt: nowISO(), updatedAt: nowISO(), accounts: [], seeded: false };
  }

  function readDb() {
    const db = driver.read(KEYS.db, null);
    if (!db || typeof db !== "object" || !Array.isArray(db.accounts)) return emptyDb();
    if (db.schema !== SCHEMA_VERSION) {
      // 预留迁移入口：结构升级时在此按版本逐级转换，而不是丢弃数据。
      console.warn("[AccountStore] schema 版本不一致，按当前结构读取。");
    }
    return db;
  }

  function writeDb(db) {
    db.updatedAt = nowISO();
    return driver.write(KEYS.db, db);
  }

  function findAccountById(db, accountId) {
    return db.accounts.find(function (item) { return item.id === accountId; }) || null;
  }

  function findByLoginOrEmail(db, identifier) {
    const key = normalizeLogin(identifier);
    return (
      db.accounts.find(function (item) {
        return item.login === key || String(item.email).toLowerCase() === key;
      }) || null
    );
  }

  /* =========================================================================
   * 6. 审计日志
   * =======================================================================*/

  function pushAudit(action, accountId, actorId, detail) {
    const entries = driver.read(KEYS.audit, []);
    entries.unshift({
      id: makeId("log"),
      at: nowISO(),
      action: action,
      accountId: accountId || null,
      actorId: actorId || accountId || null,
      detail: detail || ""
    });
    driver.write(KEYS.audit, entries.slice(0, AUDIT_LIMIT));
  }

  /* =========================================================================
   * 7. 会话
   * =======================================================================*/

  function readSession() {
    const session = driver.read(KEYS.session, null);
    if (!session || !session.token || !session.accountId) return null;
    return session;
  }

  /** 解析会话并校验其仍然有效：未过期 + 账号存在 + 账号可登录。 */
  function resolveSession() {
    const session = readSession();
    if (!session) return null;
    if (Date.parse(session.expiresAt) <= Date.now()) {
      driver.remove(KEYS.session);
      return null;
    }
    const db = readDb();
    const account = findAccountById(db, session.accountId);
    if (!account || !STATUS[account.status] || !STATUS[account.status].canLogin) {
      driver.remove(KEYS.session);
      return null;
    }
    return { session: session, account: account };
  }

  function writeSession(account, remember) {
    const ttl = remember ? SESSION_TTL_REMEMBER : SESSION_TTL_DEFAULT;
    const session = {
      token: randomToken(32),
      accountId: account.id,
      role: account.role,
      remember: Boolean(remember),
      issuedAt: nowISO(),
      expiresAt: new Date(Date.now() + ttl).toISOString()
    };
    driver.write(KEYS.session, session);
    return session;
  }

  /* =========================================================================
   * 8. 权限
   * =======================================================================*/

  function capabilitiesOf(user) {
    if (!user) return [];
    const role = ROLES[user.role];
    if (!role) return [];
    return Object.keys(CAPABILITIES).filter(function (capability) {
      return CAPABILITIES[capability].roles.indexOf(user.role) !== -1;
    });
  }

  function can(user, capability) {
    if (!user) return false;
    const rule = CAPABILITIES[capability];
    if (!rule) return false;
    return rule.roles.indexOf(user.role) !== -1;
  }

  function atLeast(user, roleId) {
    if (!user || !ROLES[user.role] || !ROLES[roleId]) return false;
    return ROLES[user.role].rank >= ROLES[roleId].rank;
  }

  /** 对外脱敏视图：password 字段绝不出数据层。 */
  function toPublic(account) {
    if (!account) return null;
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
      roleLabel: ROLES[account.role] ? ROLES[account.role].label : account.role,
      status: account.status,
      statusLabel: STATUS[account.status] ? STATUS[account.status].label : account.status,
      statusTone: STATUS[account.status] ? STATUS[account.status].tone : "muted",
      canLogin: Boolean(STATUS[account.status] && STATUS[account.status].canLogin),
      credentialAlgo: account.password ? account.password.algo : "unknown",
      security: {
        failedAttempts: account.security.failedAttempts,
        lockedUntil: account.security.lockedUntil,
        lastLoginAt: account.security.lastLoginAt,
        loginCount: account.security.loginCount
      },
      createdAt: account.createdAt,
      updatedAt: account.updatedAt,
      capabilities: capabilitiesOf(account)
    };
  }

  /* =========================================================================
   * 9. 种子账号
   *    用于让"已存在账号"在演示环境中可被真实操作；生产部署务必删除。
   * =======================================================================*/

  const SEED_ACCOUNTS = [
    {
      login: "guest", email: "guest@liminal.local", name: "演示访客",
      unit: "北京交通大学", direction: "工作台与系统能力", note: "查看公开摘要的受邀访客账号",
      role: "guest", status: "active"
    },
    {
      login: "member", email: "member@liminal.local", name: "演示成员",
      unit: "北京交通大学 自动化与智能学院", direction: "轨道交通多系统智能协同", note: "可进入工作台模块的项目成员账号",
      role: "member", status: "active"
    },
    {
      login: "admin", email: "admin@liminal.local", name: "演示管理员",
      unit: "Liminal 灵眸研究团队", direction: "工作台与系统能力", note: "负责账号角色与状态管理",
      role: "admin", status: "active"
    },
    {
      login: "pending", email: "pending@liminal.local", name: "待审核用户",
      unit: "外部合作单位", direction: "无人交通协同", note: "用于演示待审核状态无法登录",
      role: "guest", status: "pending"
    }
  ];
  const SEED_PASSWORD = "Liminal@2026";

  async function seedIfNeeded() {
    const db = readDb();
    if (db.seeded && db.accounts.length) return db;

    for (const template of SEED_ACCOUNTS) {
      if (findByLoginOrEmail(db, template.login)) continue;
      db.accounts.push({
        id: makeId("acc"),
        login: template.login,
        email: template.email,
        name: template.name,
        unit: template.unit,
        phone: "",
        direction: template.direction,
        note: template.note,
        role: template.role,
        status: template.status,
        password: await createCredential(SEED_PASSWORD),
        security: { failedAttempts: 0, lockedUntil: null, lastLoginAt: null, loginCount: 0 },
        createdAt: nowISO(),
        updatedAt: nowISO(),
        seeded: true
      });
    }
    db.seeded = true;
    writeDb(db);
    pushAudit("seed", null, null, "初始化演示账号 " + SEED_ACCOUNTS.length + " 个");
    return db;
  }

  /* =========================================================================
   * 10. 门面 API
   * =======================================================================*/

  let readyPromise = null;

  /**
   * 本地后端：数据落在浏览器 localStorage。
   * 当站点没有后端服务时（例如直接以 file:// 打开或静态托管）使用。
   */
  const LocalBackend = {
    NAMESPACE: NAMESPACE,
    KEYS: KEYS,
    ROLES: ROLES,
    STATUS: STATUS,
    CAPABILITIES: CAPABILITIES,
    DIRECTIONS: DIRECTIONS,
    SEED_PASSWORD: SEED_PASSWORD,
    STORAGE_AVAILABLE: LocalDriver.available,

    escapeHTML: escapeHTML,

    /** 幂等初始化：确保账号库存在且已播种。所有页面在使用前 await 一次。 */
    ready: function () {
      if (!readyPromise) {
        readyPromise = (async function () {
          if (!LocalDriver.available) {
            console.warn("[AccountStore] localStorage 不可用，账号功能将以只读方式运行。");
            return;
          }
          await seedIfNeeded();
        })();
      }
      return readyPromise;
    },

    /* ---------------- 会话 ---------------- */

    currentUser: function () {
      const resolved = resolveSession();
      if (!resolved) return null;
      return toPublic(resolved.account);
    },

    getSession: function () {
      const resolved = resolveSession();
      return resolved ? resolved.session : null;
    },

    isAuthenticated: function () {
      return Boolean(resolveSession());
    },

    sessionExpiresAt: function () {
      const resolved = resolveSession();
      return resolved ? resolved.session.expiresAt : null;
    },

    /* ---------------- 注册 ---------------- */

    async register(input) {
      await this.ready();
      const payload = input || {};
      const login = normalizeLogin(payload.login);
      const email = String(payload.email || "").trim();
      const name = String(payload.name || "").trim();
      const unit = String(payload.unit || "").trim();

      if (!isValidLogin(login)) return fail("login_invalid", "账号需为 3-32 位小写字母、数字或 . _ -，且以字母或数字开头。");
      if (!isValidEmail(email)) return fail("email_invalid", "请填写有效的邮箱地址。");
      if (!name) return fail("name_required", "请填写姓名。");
      if (!unit) return fail("unit_required", "请填写单位或学校。");

      const issues = passwordIssues(payload.password);
      if (issues.length) return fail("password_weak", "密码需" + issues.join("、") + "。");
      if (normalizePassword(payload.password) !== normalizePassword(payload.confirm)) {
        return fail("password_mismatch", "两次输入的密码不一致。");
      }

      const db = readDb();
      if (findByLoginOrEmail(db, login)) return fail("login_taken", "该账号已被注册。");
      if (findByLoginOrEmail(db, email)) return fail("email_taken", "该邮箱已被注册。");

      const role = ROLES[payload.role] ? payload.role : "guest";
      const account = {
        id: makeId("acc"),
        login: login,
        email: email,
        name: name,
        unit: unit,
        phone: String(payload.phone || "").trim(),
        direction: DIRECTIONS.indexOf(payload.direction) !== -1 ? payload.direction : "其他",
        note: String(payload.note || "").trim(),
        role: role,
        // 自助注册默认进入待审核；管理员在账号管理中审核通过后才可登录。
        status: "pending",
        password: await createCredential(payload.password),
        security: { failedAttempts: 0, lockedUntil: null, lastLoginAt: null, loginCount: 0 },
        createdAt: nowISO(),
        updatedAt: nowISO()
      };

      db.accounts.push(account);
      if (!writeDb(db)) return fail("storage_failed", "本地存储写入失败，注册未保存。");
      pushAudit("register", account.id, null, "注册账号 " + account.login + "，角色 " + account.role);
      return ok("registered", "注册申请已提交，审核通过后即可登录。", toPublic(account));
    },

    /* ---------------- 登录 / 登出 ---------------- */

    async login(input) {
      await this.ready();
      const payload = input || {};
      const identifier = payload.login;
      const password = normalizePassword(payload.password);

      if (!identifier || !password) return fail("empty", "请输入账号与访问密码。");

      const db = readDb();
      const account = findByLoginOrEmail(db, identifier);
      // 账号不存在与密码错误返回同一文案，避免账号枚举。
      if (!account) return fail("credential_invalid", "账号或访问密码不正确。");

      if (account.security.lockedUntil && Date.parse(account.security.lockedUntil) > Date.now()) {
        const minutes = Math.ceil((Date.parse(account.security.lockedUntil) - Date.now()) / 60000);
        return fail("locked", "登录失败次数过多，账号已锁定，请 " + minutes + " 分钟后重试。");
      }

      const matched = await verifyCredential(password, account.password);
      if (!matched) {
        account.security.failedAttempts += 1;
        if (account.security.failedAttempts >= runtimePolicy.maxFailedAttempts) {
          account.security.lockedUntil = new Date(Date.now() + runtimePolicy.lockDuration).toISOString();
          account.security.failedAttempts = 0;
          account.updatedAt = nowISO();
          writeDb(db);
          pushAudit("lock", account.id, null, "连续登录失败达到上限，账号锁定");
          return fail("locked", "登录失败次数过多，账号已锁定 15 分钟。");
        }
        account.updatedAt = nowISO();
        writeDb(db);
        const left = runtimePolicy.maxFailedAttempts - account.security.failedAttempts;
        pushAudit("login_failed", account.id, null, "密码校验失败，剩余尝试 " + left + " 次");
        // 与"账号不存在"分支返回完全一致的文案：若此处附带剩余次数，
        // 攻击者即可通过文案差异判断账号是否存在（账号枚举侧信道）。
        return fail("credential_invalid", "账号或访问密码不正确。");
      }

      if (!STATUS[account.status] || !STATUS[account.status].canLogin) {
        pushAudit("login_blocked", account.id, null, "账号状态为 " + account.status + "，拒绝建立会话");
        return fail("status_" + account.status, "该账号当前状态为「" + STATUS[account.status].label + "」，" + STATUS[account.status].description + "。");
      }

      account.security.failedAttempts = 0;
      account.security.lockedUntil = null;
      account.security.lastLoginAt = nowISO();
      account.security.loginCount += 1;
      account.updatedAt = nowISO();
      writeDb(db);

      const session = writeSession(account, payload.remember);
      pushAudit("login", account.id, account.id, "登录成功，会话至 " + session.expiresAt);
      return ok("logged_in", "登录成功。", { user: toPublic(account), session: session });
    },

    logout() {
      const resolved = resolveSession();
      if (resolved) pushAudit("logout", resolved.account.id, resolved.account.id, "主动退出登录");
      driver.remove(KEYS.session);
      return ok("logged_out", "已退出登录。");
    },

    /* ---------------- 资料维护 ---------------- */

    async updateProfile(patch) {
      await this.ready();
      const resolved = resolveSession();
      if (!resolved) return fail("unauthenticated", "登录状态已失效，请重新登录。");
      if (!can(resolved.account, "account.profile.write")) return fail("forbidden", "当前账号无权修改资料。");

      const account = resolved.account;
      const payload = patch || {};
      const db = readDb();
      const target = findAccountById(db, account.id);
      if (!target) return fail("not_found", "账号不存在。");

      if (payload.email !== undefined) {
        const email = String(payload.email).trim();
        if (!isValidEmail(email)) return fail("email_invalid", "请填写有效的邮箱地址。");
        const conflict = findByLoginOrEmail(db, email);
        if (conflict && conflict.id !== target.id) return fail("email_taken", "该邮箱已被其他账号使用。");
        target.email = email;
      }
      if (payload.name !== undefined) {
        const name = String(payload.name).trim();
        if (!name) return fail("name_required", "姓名不能为空。");
        target.name = name;
      }
      if (payload.unit !== undefined) {
        const unit = String(payload.unit).trim();
        if (!unit) return fail("unit_required", "单位或学校不能为空。");
        target.unit = unit;
      }
      if (payload.phone !== undefined) target.phone = String(payload.phone).trim();
      if (payload.direction !== undefined && DIRECTIONS.indexOf(payload.direction) !== -1) target.direction = payload.direction;
      if (payload.note !== undefined) target.note = String(payload.note).trim();

      target.updatedAt = nowISO();
      if (!writeDb(db)) return fail("storage_failed", "资料保存失败。");
      pushAudit("profile_update", target.id, account.id, "更新个人资料");
      return ok("profile_updated", "资料已保存。", toPublic(target));
    },

    async changePassword(input) {
      await this.ready();
      const resolved = resolveSession();
      if (!resolved) return fail("unauthenticated", "登录状态已失效，请重新登录。");
      if (!can(resolved.account, "account.security")) return fail("forbidden", "当前账号无权修改密码。");

      const payload = input || {};
      const matched = await verifyCredential(normalizePassword(payload.current), resolved.account.password);
      if (!matched) return fail("current_invalid", "当前访问密码不正确。");

      const issues = passwordIssues(payload.next);
      if (issues.length) return fail("password_weak", "新密码需" + issues.join("、") + "。");
      if (normalizePassword(payload.next) !== normalizePassword(payload.confirm)) {
        return fail("password_mismatch", "两次输入的新密码不一致。");
      }
      if (normalizePassword(payload.next) === normalizePassword(payload.current)) {
        return fail("password_same", "新密码不能与当前密码相同。");
      }

      const db = readDb();
      const target = findAccountById(db, resolved.account.id);
      target.password = await createCredential(payload.next);
      target.updatedAt = nowISO();
      writeDb(db);
      // 改密后轮换会话，避免旧票据继续有效。
      writeSession(target, resolved.session.remember);
      pushAudit("password_change", target.id, target.id, "修改访问密码并轮换会话");
      return ok("password_changed", "访问密码已更新。", toPublic(target));
    },

    /* ---------------- 账号状态与角色管理（管理员） ---------------- */

    async listAccounts() {
      await this.ready();
      const resolved = resolveSession();
      if (!resolved) return fail("unauthenticated", "登录状态已失效，请重新登录。");
      if (!can(resolved.account, "account.directory")) return fail("forbidden", "当前账号无权查看账号列表。");

      const db = readDb();
      const rows = db.accounts
        .slice()
        .sort(function (a, b) {
          const rankDiff = (ROLES[b.role] ? ROLES[b.role].rank : 0) - (ROLES[a.role] ? ROLES[a.role].rank : 0);
          return rankDiff || a.createdAt.localeCompare(b.createdAt);
        })
        .map(toPublic);
      return ok("listed", "已加载 " + rows.length + " 个账号。", rows);
    },

    async setStatus(accountId, status) {
      await this.ready();
      const resolved = resolveSession();
      if (!resolved) return fail("unauthenticated", "登录状态已失效，请重新登录。");
      if (!can(resolved.account, "account.manage")) return fail("forbidden", "当前账号无权调整账号状态。");
      if (!STATUS[status]) return fail("status_unknown", "未知的账号状态。");
      if (accountId === resolved.account.id) return fail("self_forbidden", "不能调整本人账号的状态。");

      const db = readDb();
      const target = findAccountById(db, accountId);
      if (!target) return fail("not_found", "账号不存在。");

      target.status = status;
      target.updatedAt = nowISO();
      writeDb(db);
      pushAudit("status_change", target.id, resolved.account.id, "状态调整为 " + STATUS[status].label);
      return ok("status_updated", target.name + " 的状态已调整为「" + STATUS[status].label + "」。", toPublic(target));
    },

    async setRole(accountId, role) {
      await this.ready();
      const resolved = resolveSession();
      if (!resolved) return fail("unauthenticated", "登录状态已失效，请重新登录。");
      if (!can(resolved.account, "account.manage")) return fail("forbidden", "当前账号无权调整账号角色。");
      if (!ROLES[role]) return fail("role_unknown", "未知的角色。");
      if (accountId === resolved.account.id) return fail("self_forbidden", "不能调整本人的角色。");

      const db = readDb();
      const target = findAccountById(db, accountId);
      if (!target) return fail("not_found", "账号不存在。");

      target.role = role;
      target.updatedAt = nowISO();
      writeDb(db);
      pushAudit("role_change", target.id, resolved.account.id, "角色调整为 " + ROLES[role].label);
      return ok("role_updated", target.name + " 的角色已调整为「" + ROLES[role].label + "」。", toPublic(target));
    },

    async resetPassword(accountId, nextPassword) {
      await this.ready();
      const resolved = resolveSession();
      if (!resolved) return fail("unauthenticated", "登录状态已失效，请重新登录。");
      if (!can(resolved.account, "account.manage")) return fail("forbidden", "当前账号无权重置密码。");

      const issues = passwordIssues(nextPassword);
      if (issues.length) return fail("password_weak", "临时密码需" + issues.join("、") + "。");

      const db = readDb();
      const target = findAccountById(db, accountId);
      if (!target) return fail("not_found", "账号不存在。");

      target.password = await createCredential(nextPassword);
      target.security.failedAttempts = 0;
      target.security.lockedUntil = null;
      target.updatedAt = nowISO();
      writeDb(db);
      pushAudit("password_reset", target.id, resolved.account.id, "由管理员重置访问密码");
      return ok("password_reset", "已为 " + target.name + " 重置访问密码。", toPublic(target));
    },

    /* ---------------- 权限查询 ---------------- */

    can: can,
    atLeast: atLeast,
    capabilitiesOf: capabilitiesOf,
    roleOf: function (roleId) { return ROLES[roleId] || null; },
    statusOf: function (statusId) { return STATUS[statusId] || null; },

    /* ---------------- 审计 ---------------- */

    auditLog(limit) {
      const entries = driver.read(KEYS.audit, []);
      return entries.slice(0, limit || 20);
    },

    /* ---------------- 维护 ---------------- */

    /** 清空演示数据。仅用于本地调试，页面不暴露该入口。 */
    async resetDemoData() {
      driver.remove(KEYS.db);
      driver.remove(KEYS.session);
      driver.remove(KEYS.audit);
      readyPromise = null;
      await this.ready();
      return ok("reset", "演示账号数据已重置。");
    }
  };

  /* =========================================================================
   * 11. 远程后端：账号数据存放在服务端 SQLite
   *     与 LocalBackend 保持完全相同的对外契约，页面层无需区分。
   * =======================================================================*/

  const RemoteBackend = {
    user: null,
    expiresAt: null,
    accounts: [],
    auditEntries: [],

    async request(method, url, body) {
      const options = {
        method: method,
        credentials: "same-origin", // 带上 HttpOnly 会话 Cookie
        headers: { Accept: "application/json" }
      };
      if (body !== undefined) {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(body);
      }
      try {
        const response = await fetch(url, options);
        const payload = await response.json().catch(function () { return null; });
        if (!payload) return fail("bad_response", "服务端返回了无法解析的内容。");
        return payload;
      } catch (error) {
        return fail("network_error", "无法连接账号服务，请确认后端已启动。");
      }
    },

    /** 同步服务端会话到本地缓存，供同步读取方法使用。 */
    async refresh() {
      const result = await this.request("GET", "/api/auth/session");
      if (result.ok) {
        this.user = result.data.user;
        this.expiresAt = result.data.session.expiresAt;
        await this.refreshAudit();
      } else {
        this.user = null;
        this.expiresAt = null;
        this.auditEntries = [];
      }
      return this.user;
    },

    async refreshAudit() {
      const result = await this.request("GET", "/api/account/audit?limit=50");
      this.auditEntries = result.ok ? result.data : [];
    },

    /* --- 同步读取 --- */
    currentUser: function () { return this.user; },
    isAuthenticated: function () { return Boolean(this.user); },
    sessionExpiresAt: function () { return this.expiresAt; },
    getSession: function () { return this.expiresAt ? { expiresAt: this.expiresAt } : null; },
    auditLog: function (limit) { return this.auditEntries.slice(0, limit || 20); },

    /* --- 异步操作 --- */
    async register(input) {
      return this.request("POST", "/api/auth/register", input);
    },

    async login(input) {
      const result = await this.request("POST", "/api/auth/login", input);
      if (result.ok) {
        this.user = result.data.user;
        this.expiresAt = result.data.session.expiresAt;
        await this.refreshAudit();
      }
      return result;
    },

    async logout() {
      const result = await this.request("POST", "/api/auth/logout");
      this.user = null;
      this.expiresAt = null;
      this.auditEntries = [];
      return result;
    },

    async updateProfile(patch) {
      const result = await this.request("PATCH", "/api/account/profile", patch);
      if (result.ok) {
        this.user = result.data;
        await this.refreshAudit();
      }
      return result;
    },

    async changePassword(input) {
      const result = await this.request("POST", "/api/account/password", input);
      if (result.ok) {
        this.user = result.data;
        await this.refreshAudit();
      }
      return result;
    },

    async listAccounts() {
      const result = await this.request("GET", "/api/admin/accounts");
      if (result.ok) this.accounts = result.data;
      return result;
    },

    async setStatus(accountId, status) {
      const result = await this.request(
        "PATCH", "/api/admin/accounts/" + encodeURIComponent(accountId) + "/status", { status: status }
      );
      if (result.ok) await this.refreshAudit();
      return result;
    },

    async setRole(accountId, role) {
      const result = await this.request(
        "PATCH", "/api/admin/accounts/" + encodeURIComponent(accountId) + "/role", { role: role }
      );
      if (result.ok) await this.refreshAudit();
      return result;
    },

    async resetPassword(accountId, nextPassword) {
      const result = await this.request(
        "POST", "/api/admin/accounts/" + encodeURIComponent(accountId) + "/password", { password: nextPassword }
      );
      if (result.ok) await this.refreshAudit();
      return result;
    },

    async resetDemoData() {
      return fail("not_supported", "当前账号数据存放在服务端数据库，请在服务端执行重置。");
    }
  };

  /* =========================================================================
   * 12. 后端探测与门面
   * =======================================================================*/

  let activeBackend = null;
  let bootstrapPromise = null;

  /** 探测同源 /api/health；file:// 或静态托管场景直接判否。 */
  async function detectRemoteBackend() {
    if (typeof fetch !== "function") return false;
    if (typeof location !== "undefined" && location.protocol === "file:") return false;

    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timer = controller ? setTimeout(function () { controller.abort(); }, 1500) : null;
    try {
      const response = await fetch("/api/health", {
        signal: controller ? controller.signal : undefined,
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      });
      if (!response.ok) return false;
      const payload = await response.json();
      return Boolean(payload && payload.ok && payload.data && payload.data.storage);
    } catch (error) {
      return false;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** 用服务端下发的元数据覆盖本地常量，避免前后端规则漂移。 */
  async function syncRemoteMetadata() {
    const result = await RemoteBackend.request("GET", "/api/metadata");
    if (!result.ok) return;

    const meta = result.data;
    const replace = (target, source) => {
      if (!source) return;
      Object.keys(target).forEach(function (key) { delete target[key]; });
      Object.assign(target, source);
    };

    replace(ROLES, meta.roles);
    replace(STATUS, meta.status);
    replace(CAPABILITIES, meta.capabilities);
    if (Array.isArray(meta.directions) && meta.directions.length) {
      DIRECTIONS.length = 0;
      meta.directions.forEach(function (item) { DIRECTIONS.push(item); });
    }
    if (meta.policy) {
      if (meta.policy.maxFailedAttempts) runtimePolicy.maxFailedAttempts = meta.policy.maxFailedAttempts;
      if (meta.policy.lockDuration) runtimePolicy.lockDuration = meta.policy.lockDuration;
    }
  }

  async function selectBackend() {
    if (await detectRemoteBackend()) {
      activeBackend = RemoteBackend;
      await syncRemoteMetadata();
      await RemoteBackend.refresh();
    } else {
      activeBackend = LocalBackend;
      await LocalBackend.ready();
    }
    return activeBackend;
  }

  const AccountStore = {
    NAMESPACE: NAMESPACE,
    KEYS: KEYS,
    ROLES: ROLES,
    STATUS: STATUS,
    CAPABILITIES: CAPABILITIES,
    DIRECTIONS: DIRECTIONS,
    SEED_PASSWORD: SEED_PASSWORD,
    STORAGE_AVAILABLE: LocalDriver.available,
    get MAX_FAILED_ATTEMPTS() { return runtimePolicy.maxFailedAttempts; },
    get LOCK_DURATION() { return runtimePolicy.lockDuration; },

    /** "remote"（服务端数据库） | "local"（浏览器存储） | "pending"（尚未探测） */
    get MODE() {
      if (activeBackend === RemoteBackend) return "remote";
      if (activeBackend === LocalBackend) return "local";
      return "pending";
    },

    get STORAGE_LABEL() {
      if (activeBackend === RemoteBackend) return "服务端 SQLite 数据库";
      if (activeBackend === LocalBackend) return "浏览器本地存储";
      return "探测中";
    },

    escapeHTML: escapeHTML,

    /** 幂等初始化：探测后端并建立会话缓存。页面在使用前 await 一次即可。 */
    ready: function () {
      if (!bootstrapPromise) bootstrapPromise = selectBackend();
      return bootstrapPromise;
    },

    /* ---------------- 会话（同步读取） ---------------- */

    currentUser: function () {
      return activeBackend ? activeBackend.currentUser() : null;
    },
    getSession: function () {
      return activeBackend ? activeBackend.getSession() : null;
    },
    isAuthenticated: function () {
      return activeBackend ? activeBackend.isAuthenticated() : false;
    },
    sessionExpiresAt: function () {
      return activeBackend ? activeBackend.sessionExpiresAt() : null;
    },
    auditLog: function (limit) {
      return activeBackend ? activeBackend.auditLog(limit) : [];
    },

    /* ---------------- 账号操作（异步） ---------------- */

    async register(input) {
      await this.ready();
      return activeBackend.register(input);
    },
    async login(input) {
      await this.ready();
      return activeBackend.login(input);
    },
    async logout() {
      await this.ready();
      return activeBackend.logout();
    },
    async updateProfile(patch) {
      await this.ready();
      return activeBackend.updateProfile(patch);
    },
    async changePassword(input) {
      await this.ready();
      return activeBackend.changePassword(input);
    },
    async listAccounts() {
      await this.ready();
      return activeBackend.listAccounts();
    },
    async setStatus(accountId, status) {
      await this.ready();
      return activeBackend.setStatus(accountId, status);
    },
    async setRole(accountId, role) {
      await this.ready();
      return activeBackend.setRole(accountId, role);
    },
    async resetPassword(accountId, nextPassword) {
      await this.ready();
      return activeBackend.resetPassword(accountId, nextPassword);
    },
    async resetDemoData() {
      await this.ready();
      return activeBackend.resetDemoData();
    },

    /* ---------------- 权限（纯本地计算） ---------------- */

    can: can,
    atLeast: atLeast,
    capabilitiesOf: capabilitiesOf,
    roleOf: function (roleId) { return ROLES[roleId] || null; },
    statusOf: function (statusId) { return STATUS[statusId] || null; }
  };

  global.AccountStore = AccountStore;
})(window);
