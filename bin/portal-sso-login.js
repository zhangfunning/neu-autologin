#!/usr/bin/env node

const fs = require("fs");
const { chromium } = require("playwright-core");

const DEFAULT_PORTAL_HOST = "https://ipgw.neu.edu.cn/";
const DEFAULT_AC_ID = "16";
const BROWSER_CANDIDATES = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
];
let outputWritten = false;

function toSingleLine(text) {
  return String(text || "")
    .replace(/\s+/g, " ")
    .trim();
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function emitOutput(payload) {
  if (outputWritten) {
    return;
  }
  outputWritten = true;
  process.stdout.write(JSON.stringify(payload));
}

function normalizePortalHost(input) {
  let host = String(input || "").trim();
  if (!host) {
    host = DEFAULT_PORTAL_HOST;
  }

  if (!/^https?:\/\//i.test(host)) {
    host = `https://${host}`;
  }

  host = host.replace(/^http:\/\/ipgw\.neu\.edu\.cn/i, "https://ipgw.neu.edu.cn");
  if (!host.endsWith("/")) {
    host += "/";
  }
  return host;
}

function toHttpHost(host) {
  return String(host || "").replace(/^https:\/\//i, "http://");
}

function findBrowserExecutable() {
  for (const candidate of BROWSER_CANDIDATES) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error("未找到 Edge 或 Chrome 浏览器。");
}

async function readInput() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  if (chunks.length === 0) {
    throw new Error("stdin 输入为空。");
  }

  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) {
    throw new Error("stdin 输入为空。");
  }

  return JSON.parse(raw);
}

function isConnectedPage(url, content) {
  const u = String(url || "");
  const body = String(content || "");
  return (
    /srun_portal_success/i.test(u) ||
    body.includes('id="logout"') ||
    body.includes('id="logout-all"') ||
    body.includes("logout-all-success")
  );
}

function isLoginPage(content) {
  const body = String(content || "");
  return (
    body.includes('id="login-sso"') ||
    body.includes('id="login-account"') ||
    body.includes('id="loginForm"') ||
    body.includes('id="index_login_btn"')
  );
}

async function safeGoto(page, url, timeout) {
  try {
    await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout,
    });
  } catch {
    // continue with fallback probes
  }
}

async function tryGetPageContent(page) {
  try {
    return await page.content();
  } catch {
    return "";
  }
}

function tryParseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function extractJsonFromJsonp(text) {
  const raw = String(text || "").trim();
  if (!raw) {
    return null;
  }

  const firstParen = raw.indexOf("(");
  const lastParen = raw.lastIndexOf(")");
  if (firstParen > 0 && lastParen > firstParen) {
    const maybe = raw.slice(firstParen + 1, lastParen).trim();
    return tryParseJson(maybe);
  }

  return tryParseJson(raw);
}

function looksLikeIp(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(String(value || "").trim());
}

function parseCsvOnlineInfo(text) {
  const raw = String(text || "").trim();
  const parts = raw.split(",");
  if (parts.length < 9) {
    return null;
  }

  const username = String(parts[0] || "").trim();
  const onlineIp = String(parts[8] || "").trim();
  if (!username || !looksLikeIp(onlineIp)) {
    return null;
  }

  return {
    known: true,
    online: true,
    username,
    onlineIp,
    source: "csv",
  };
}

function parseRadUserInfoText(text) {
  const raw = String(text || "").trim();
  if (!raw) {
    return { known: false, online: false, source: "empty", username: "", onlineIp: "" };
  }

  if (/not_online_error/i.test(raw)) {
    return { known: true, online: false, source: "not-online", username: "", onlineIp: "" };
  }

  const csv = parseCsvOnlineInfo(raw);
  if (csv) {
    return csv;
  }

  const json = extractJsonFromJsonp(raw);
  if (!json || typeof json !== "object") {
    return { known: false, online: false, source: "unknown-format", username: "", onlineIp: "" };
  }

  const error = String(json.error || json.res || "").toLowerCase();
  const username = String(
    json.username ||
      json.user_name ||
      json.user ||
      json.uid ||
      json.billing_id ||
      ""
  ).trim();
  const onlineIp = String(json.online_ip || json.client_ip || json.ip || "").trim();

  if (error.includes("not_online_error")) {
    return { known: true, online: false, source: "jsonp-not-online", username, onlineIp };
  }

  if (error === "ok" || looksLikeIp(onlineIp)) {
    return { known: true, online: true, source: "jsonp-online", username, onlineIp };
  }

  return { known: false, online: false, source: "jsonp-unknown", username, onlineIp };
}

async function fetchRadUserInfo(context, portalHost, trace, tag) {
  const cb = `cb_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;
  const url = new URL("/cgi-bin/rad_user_info", portalHost);
  url.searchParams.set("callback", cb);
  url.searchParams.set("_", String(Date.now()));

  try {
    const response = await context.request.get(url.toString(), {
      timeout: 12000,
      failOnStatusCode: false,
    });
    const body = await response.text();
    const parsed = parseRadUserInfoText(body);
    trace.push(
      `${tag}-rad status=${response.status()} known=${parsed.known} online=${parsed.online} source=${parsed.source} user=${parsed.username || "-"} ip=${parsed.onlineIp || "-"}`
    );
    return {
      ...parsed,
      status: response.status(),
      body,
    };
  } catch (error) {
    trace.push(`${tag}-rad error=${toSingleLine(error && error.message ? error.message : error)}`);
    return {
      known: false,
      online: false,
      source: "request-error",
      username: "",
      onlineIp: "",
      status: 0,
      body: "",
    };
  }
}

async function detectPageState(page, successUrl, trace, tag) {
  await safeGoto(page, successUrl.toString(), 18000);
  const finalUrl = page.url();
  const content = await tryGetPageContent(page);
  const online = isConnectedPage(finalUrl, content);
  const login = isLoginPage(content);
  const known = online || login;
  trace.push(`${tag}-page known=${known} online=${online} url=${finalUrl}`);
  return {
    known,
    online,
    finalUrl,
    content,
  };
}

async function probeOnlineState(context, page, urls, trace, tag) {
  const api = await fetchRadUserInfo(context, urls.portalHost, trace, tag);
  const pageState = await detectPageState(page, urls.successUrl, trace, tag);

  if (api.known) {
    return {
      known: true,
      online: api.online,
      source: "rad",
      username: api.username || "",
      onlineIp: api.onlineIp || "",
      finalUrl: pageState.finalUrl,
      content: pageState.content,
    };
  }

  if (pageState.known) {
    return {
      known: true,
      online: pageState.online,
      source: "page",
      username: "",
      onlineIp: "",
      finalUrl: pageState.finalUrl,
      content: pageState.content,
    };
  }

  return {
    known: false,
    online: false,
    source: "unknown",
    username: "",
    onlineIp: "",
    finalUrl: pageState.finalUrl,
    content: pageState.content,
  };
}

async function clickFirstExisting(page, selectors) {
  for (const selector of selectors) {
    try {
      await page.waitForLoadState("domcontentloaded", { timeout: 5000 }).catch(() => {});
      const element = await page.$(selector);
      if (!element) {
        continue;
      }

      await element.click({ timeout: 5000 });
      return selector;
    } catch {
      // try next selector
    }
  }
  return null;
}

async function submitCredentials(loginPage, username, password) {
  await loginPage.waitForSelector("#un", { timeout: 30000 });
  await loginPage.waitForSelector("#pd", { timeout: 30000 });
  await loginPage.fill("#un", username);
  await loginPage.fill("#pd", password);

  const submitSelector = (await loginPage.$("#index_login_btn"))
    ? "#index_login_btn"
    : "button[type='submit'], input[type='submit']";
  await loginPage.click(submitSelector, { timeout: 10000 });
}

function buildUrls(input, acId, portalHost) {
  const portalHttpHost = toHttpHost(portalHost);

  const portalUrl = new URL("/srun_portal_pc", portalHost);
  portalUrl.searchParams.set("ac_id", acId);
  portalUrl.searchParams.set("theme", "pro");

  const successUrl = new URL("/srun_portal_success", portalHost);
  successUrl.searchParams.set("ac_id", acId);
  successUrl.searchParams.set("theme", "pro");

  let serviceUrl;
  if (input.ServiceBaseUrl) {
    try {
      serviceUrl = new URL(String(input.ServiceBaseUrl).trim());
    } catch {
      serviceUrl = new URL("/srun_portal_sso", portalHttpHost);
    }
  } else {
    serviceUrl = new URL("/srun_portal_sso", portalHttpHost);
  }

  if (/ipgw\.neu\.edu\.cn/i.test(serviceUrl.host)) {
    serviceUrl.protocol = "http:";
  }
  if (!serviceUrl.searchParams.has("ac_id")) {
    serviceUrl.searchParams.set("ac_id", acId);
  }

  const tpassLoginUrl = `https://pass.neu.edu.cn/tpass/login?service=${encodeURIComponent(serviceUrl.toString())}`;
  const tpassLogoutUrl = `https://pass.neu.edu.cn/tpass/logout?service=${encodeURIComponent(portalHost)}`;

  return {
    portalHost,
    portalHttpHost,
    portalUrl,
    successUrl,
    serviceUrl,
    tpassLoginUrl,
    tpassLogoutUrl,
  };
}

async function doLoginFlow({ input, acId, urls, trace, context }) {
  if (!input.Username || !input.Password) {
    throw new Error("账号或密码为空。");
  }

  const page = await context.newPage();
  const before = await probeOnlineState(context, page, urls, trace, "before-login");
  if (before.known && before.online) {
    return {
      ok: true,
      acId,
      finalUrl: before.finalUrl,
      successPage: true,
      loginPage: false,
      errorMessage: "",
      message: "当前已是登录状态。",
      trace,
    };
  }

  await safeGoto(page, urls.portalUrl.toString(), 30000);
  trace.push(`portal ${page.url()}`);

  const popupPromise = context.waitForEvent("page", { timeout: 8000 }).catch(() => null);
  let clickedSso = false;
  try {
    await page.waitForLoadState("domcontentloaded", { timeout: 6000 }).catch(() => {});
    const ssoBtn = await page.$("#login-sso");
    if (ssoBtn) {
      await ssoBtn.click({ timeout: 10000 });
      clickedSso = true;
    }
  } catch (error) {
    trace.push(`click-login-sso error=${toSingleLine(error && error.message ? error.message : error)}`);
  }

  if (!clickedSso) {
    await safeGoto(page, urls.tpassLoginUrl, 30000);
  }

  let loginPage = await popupPromise;
  if (!loginPage) {
    loginPage = page;
  }
  await loginPage.waitForLoadState("domcontentloaded", { timeout: 30000 }).catch(() => {});

  if (!/pass\.neu\.edu\.cn/i.test(loginPage.url())) {
    await safeGoto(loginPage, urls.tpassLoginUrl, 30000);
  }
  trace.push(`login ${loginPage.url()}`);

  await submitCredentials(loginPage, input.Username, input.Password);
  await Promise.race([
    loginPage.waitForURL(/ticket=/i, { timeout: 45000 }),
    loginPage.waitForURL(/srun_portal_success/i, { timeout: 45000 }),
    loginPage.waitForLoadState("domcontentloaded", { timeout: 45000 }),
  ]).catch(() => {});

  trace.push(`after-submit ${loginPage.url()}`);

  for (let i = 0; i < 4; i++) {
    const verify = await probeOnlineState(context, loginPage, urls, trace, `verify-login-${i + 1}`);
    if (verify.known && verify.online) {
      return {
        ok: true,
        acId,
        finalUrl: verify.finalUrl,
        successPage: true,
        loginPage: false,
        errorMessage: "",
        message: "登录成功。",
        trace,
      };
    }
    await wait(2000);
  }

  const errorMessage = await loginPage
    .locator("#errormsghide, #errormsg, .error, .msg-error")
    .first()
    .textContent()
    .catch(() => "");
  const finalUrl = loginPage.url();
  const finalContent = await tryGetPageContent(loginPage);

  return {
    ok: false,
    acId,
    finalUrl,
    successPage: false,
    loginPage: isLoginPage(finalContent),
    errorMessage: toSingleLine(errorMessage),
    message: toSingleLine(errorMessage) || "登录没有到达成功状态。",
    trace,
  };
}

async function tryLogoutByApi(context, urls, acId, username, onlineIp, trace) {
  if (!username || !onlineIp) {
    trace.push("logout-api skip (missing username or ip)");
    return { ok: false, responseOk: false };
  }

  const cb = `cb_${Date.now()}_${Math.floor(Math.random() * 1_000_000)}`;
  const logoutUrl = new URL("/cgi-bin/srun_portal", urls.portalHttpHost);
  logoutUrl.searchParams.set("callback", cb);
  logoutUrl.searchParams.set("action", "logout");
  logoutUrl.searchParams.set("username", username);
  logoutUrl.searchParams.set("ip", onlineIp);
  logoutUrl.searchParams.set("ac_id", acId);
  logoutUrl.searchParams.set("_", String(Date.now()));

  try {
    const response = await context.request.get(logoutUrl.toString(), {
      timeout: 20000,
      failOnStatusCode: false,
    });
    const body = await response.text();
    const json = extractJsonFromJsonp(body);
    const responseOk = !!json && String(json.error || json.res || "").toLowerCase() === "ok";
    trace.push(`logout-api status=${response.status()} responseOk=${responseOk} url=${logoutUrl.toString()}`);
    return { ok: true, responseOk };
  } catch (error) {
    trace.push(`logout-api error=${toSingleLine(error && error.message ? error.message : error)}`);
    return { ok: false, responseOk: false };
  }
}

async function doLogoutFlow({ acId, urls, trace, context }) {
  const page = await context.newPage();
  const before = await probeOnlineState(context, page, urls, trace, "before-logout");
  if (before.known && !before.online) {
    return {
      ok: true,
      acId,
      finalUrl: before.finalUrl,
      successPage: false,
      loginPage: true,
      alreadyLoggedOut: true,
      errorMessage: "",
      message: "当前已是未登录状态。",
      trace,
    };
  }

  await safeGoto(page, urls.successUrl.toString(), 30000);
  trace.push(`success-page ${page.url()}`);
  const clicked = await clickFirstExisting(page, [
    "#logout",
    "#logout-all",
    "#logout-all-success",
    "button[id*='logout']",
    "a[id*='logout']",
  ]);
  trace.push(`clicked ${clicked || "none"}`);

  if (clicked) {
    await page.waitForLoadState("domcontentloaded", { timeout: 15000 }).catch(() => {});
    await wait(1500);
    const afterClick = await probeOnlineState(context, page, urls, trace, "after-click");
    if (afterClick.known && !afterClick.online) {
      return {
        ok: true,
        acId,
        finalUrl: afterClick.finalUrl,
        successPage: false,
        loginPage: true,
        alreadyLoggedOut: false,
        errorMessage: "",
        message: "已注销校园网登录。",
        trace,
      };
    }
  }

  const info = await fetchRadUserInfo(context, urls.portalHost, trace, "logout-info");
  const logoutApi = await tryLogoutByApi(
    context,
    urls,
    acId,
    info.username,
    info.onlineIp,
    trace
  );
  if (logoutApi.ok) {
    await wait(1200);
    const afterApi = await probeOnlineState(context, page, urls, trace, "after-logout-api");
    if (afterApi.known && !afterApi.online) {
      return {
        ok: true,
        acId,
        finalUrl: afterApi.finalUrl,
        successPage: false,
        loginPage: true,
        alreadyLoggedOut: false,
        errorMessage: "",
        message: "已注销校园网登录。",
        trace,
      };
    }
  }

  await safeGoto(page, urls.tpassLogoutUrl, 20000);
  trace.push(`tpass-logout ${page.url()}`);
  await wait(1200);
  const afterCas = await probeOnlineState(context, page, urls, trace, "after-cas-logout");
  if (afterCas.known && !afterCas.online) {
    return {
      ok: true,
      acId,
      finalUrl: afterCas.finalUrl,
      successPage: false,
      loginPage: true,
      alreadyLoggedOut: false,
      errorMessage: "",
      message: "已注销校园网登录。",
      trace,
    };
  }

  return {
    ok: false,
    acId,
    finalUrl: afterCas.finalUrl || page.url(),
    successPage: afterCas.online,
    loginPage: !afterCas.online,
    alreadyLoggedOut: false,
    errorMessage: "",
    message: afterCas.known ? "注销后仍检测为在线状态。" : "注销状态未知，请重试。",
    trace,
  };
}

async function main() {
  const input = await readInput();
  const modeInput = String(input.Mode || "login").toLowerCase();
  const mode = modeInput === "logout" ? "logout" : "login";

  const acId = String(input.AcId || DEFAULT_AC_ID).trim() || DEFAULT_AC_ID;
  const portalHost = normalizePortalHost(input.PortalHost || DEFAULT_PORTAL_HOST);
  const urls = buildUrls(input, acId, portalHost);

  const browser = await chromium.launch({
    executablePath: findBrowserExecutable(),
    headless: true,
    args: ["--disable-gpu", "--disable-dev-shm-usage"],
  });

  const trace = [];
  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
    });

    const payload =
      mode === "logout"
        ? await doLogoutFlow({ acId, urls, trace, context })
        : await doLoginFlow({ input, acId, urls, trace, context });

    payload.mode = mode;
    payload.portalUrl = urls.portalUrl.toString();
    emitOutput(payload);
    if (!payload.ok) {
      process.exitCode = 1;
    }
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  const payload = {
    ok: false,
    message: toSingleLine(error && error.message ? error.message : error),
  };
  emitOutput(payload);
  process.exitCode = 1;
});
