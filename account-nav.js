/*!
 * Liminal 灵眸 · 全站登录态入口同步
 * ---------------------------------------------------------------------------
 * 作用：让公开页面的导航入口随登录状态切换，避免"已登录却仍显示云台登录"
 *       的体验断裂，同时不改变各页面已有的导航 DOM 结构。
 *
 * 接入方式：在各页面 </body> 前引入
 *   <script src="account-nav.js"></script>            （根目录页面）
 *   <script src="../account-nav.js"></script>         （model-market 页面）
 *
 * 覆盖的入口：
 *   公开页导航  a.nav-action[href$="login.html"]       云台登录 / 账号中心
 *   首页访问区  .access-login-action a[href$="login.html"]
 *   模型生态页  .workspace-link[href$="login.html"]     进入工作台 / 账号中心
 * 说明：形如 login.html#apply 的"申请访问"入口不在同步范围内。
 * ---------------------------------------------------------------------------
 */
(function () {
  "use strict";

  const Store = window.AccountStore;
  if (!Store) return;

  const script = document.currentScript || (function () {
    const list = document.getElementsByTagName("script");
    for (let i = list.length - 1; i >= 0; i -= 1) {
      if (/account-nav\.js(\?|$)/.test(list[i].src)) return list[i];
    }
    return null;
  })();

  const base = script ? script.src.replace(/[^/]*$/, "") : "";
  const ACCOUNT_URL = base + "account.html";
  const LOGIN_URL = base + "login.html";

  function applyEntryState() {
    const user = Store.currentUser();

    document.querySelectorAll('a.nav-action[href$="login.html"]').forEach(function (link) {
      link.textContent = user ? "账号中心" : "云台登录";
      link.setAttribute("href", user ? ACCOUNT_URL : LOGIN_URL);
      if (user) link.setAttribute("title", user.name + " · " + user.roleLabel);
      else link.removeAttribute("title");
    });

    document.querySelectorAll('.access-login-action a[href$="login.html"], a.access-entry-btn[href$="login.html"]').forEach(function (link) {
      link.textContent = user ? "进入账号中心 →" : "进入云平台 →";
      link.setAttribute("href", user ? ACCOUNT_URL : LOGIN_URL);
    });

    document.querySelectorAll('a.workspace-link[href$="login.html"]').forEach(function (link) {
      link.textContent = user ? "账号中心 ↗" : "进入工作台 ↗";
      link.setAttribute("href", user ? ACCOUNT_URL : LOGIN_URL);
      if (user) link.setAttribute("title", user.name + " · " + user.roleLabel);
      else link.removeAttribute("title");
    });

    document.documentElement.dataset.accountState = user ? "authenticated" : "anonymous";
  }

  function start() {
    applyEntryState();

    // 跨标签页同步：在账号中心退出登录后，其他已打开页面自动回到未登录入口。
    window.addEventListener("storage", function (event) {
      if (!event.key || event.key.indexOf(Store.NAMESPACE) === 0) applyEntryState();
    });

    // 从缓存返回页面时重新校对一次状态（会话可能已过期）。
    window.addEventListener("pageshow", applyEntryState);

    // 会话到期后自动回落为未登录入口。
    const expiresAt = Store.sessionExpiresAt();
    if (expiresAt) {
      const remaining = Date.parse(expiresAt) - Date.now();
      if (remaining > 0 && remaining < 2147483647) setTimeout(applyEntryState, remaining + 1000);
    }
  }

  Store.ready().then(start, start);
})();
