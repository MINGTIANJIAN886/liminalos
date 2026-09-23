/*!
 * Liminal 灵眸 · 首次启动播种
 * ---------------------------------------------------------------------------
 * 仅当 accounts 表为空时写入演示账号，保证数据库始终有可登录对象。
 * 生产部署：设置 LIMINAL_SKIP_SEED=1 跳过播种，改用 /api/setup/import 或手工建号。
 * ---------------------------------------------------------------------------
 */
"use strict";

const crypto = require("node:crypto");
const db = require("./db");
const auth = require("./auth");

const SEED_PASSWORD = "Liminal@2026";

const SEED_ACCOUNTS = [
  { login: "guest", email: "guest@liminal.local", name: "演示访客", unit: "北京交通大学", direction: "工作台与系统能力", role: "guest", status: "active", note: "查看公开摘要的受邀访客账号" },
  { login: "member", email: "member@liminal.local", name: "演示成员", unit: "北京交通大学 自动化与智能学院", direction: "轨道交通多系统智能协同", role: "member", status: "active", note: "可进入工作台模块的项目成员账号" },
  { login: "admin", email: "admin@liminal.local", name: "演示管理员", unit: "Liminal 灵眸研究团队", direction: "工作台与系统能力", role: "admin", status: "active", note: "负责账号角色与状态管理" },
  { login: "pending", email: "pending@liminal.local", name: "待审核用户", unit: "外部合作单位", direction: "无人交通协同", role: "guest", status: "pending", note: "用于演示待审核状态无法登录" }
];

function seedIfEmpty() {
  if (process.env.LIMINAL_SKIP_SEED === "1") return { seeded: 0, skipped: true };
  if (db.stmt.countAccounts.get().n > 0) return { seeded: 0, skipped: true };

  let seeded = 0;

  db.transaction(function () {
    SEED_ACCOUNTS.forEach(function (template) {
      const credential = auth.createCredential(SEED_PASSWORD);
      const now = db.nowISO();
      db.stmt.insertAccount.run(
        "acc_" + crypto.randomBytes(12).toString("hex"),
        template.login,
        template.email,
        template.name,
        template.unit,
        "",
        template.direction,
        template.note,
        template.role,
        template.status,
        credential.algo,
        credential.salt,
        credential.hash,
        credential.iterations,
        now,
        now
      );
      seeded += 1;
    });
  });

  auth.audit("seed", null, null, "初始化演示账号 " + seeded + " 个");
  return { seeded: seeded, skipped: false };
}

module.exports = { seedIfEmpty, SEED_ACCOUNTS, SEED_PASSWORD };
