import { chromium, devices } from "@playwright/test";

const browser = await chromium.launch({ headless: true });
const ctx = await browser.newContext({ ...devices["Pixel 7"] });
const page = await ctx.newPage();

const errs = [];
const logs = [];
const reloads = [];
page.on("pageerror", (e) => errs.push(`PAGEERR: ${e.message}\n${e.stack?.split("\n").slice(0,5).join("\n")}`));
page.on("console", (m) => logs.push(`[${m.type()}] ${m.text()}`));
page.on("crash", () => errs.push("PAGE CRASHED"));
page.on("framenavigated", (f) => { if (f === page.mainFrame()) reloads.push(f.url()); });

const TOKEN = "http://localhost:8099#J-SoWXCo6Q5nR1KlVZH9g_u2vzt3DPEF-RS4GT4f9mY.1fdgzPNpFccsqQ8oyDsxf-4Zk10CR0NtcoooAMK1HiE";
// Attach to pty-relay-claude (a real session running this Claude in the user's pty fleet).
const hashIdx = TOKEN.indexOf("#");
const url = TOKEN.slice(0, hashIdx) + "/pty-relay-claude" + TOKEN.slice(hashIdx);
console.log("URL: ...redacted...");

await page.goto(url);
await page.waitForTimeout(5000);

console.log("STATUS:", await page.locator("#status-overlay").textContent().catch(() => "?"));
console.log("TERMINAL-VISIBLE:", await page.locator("#terminal-view").evaluate(el => getComputedStyle(el).display).catch(() => "?"));
console.log("NAVIGATIONS:", reloads.length, "->", reloads.slice(0, 3));
console.log("---errors---");
for (const e of errs.slice(0, 10)) console.log(e);
console.log("---last logs---");
for (const l of logs.slice(-15)) console.log(l);

await browser.close();
