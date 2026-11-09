// Long-running browser session with an HTTP control port, for exploring and for scripted scenarios.
// Usage: tsx driver/session.ts <runDir> <proxy> <chain> <ownerKeyName> [port]
import { chromium, type BrowserContext, type Page } from "playwright";
import { launch, onboard, onboardingTab, toggles, mmKeys } from "./mm.js";
import { createServer } from "node:http";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { Signer } from "./signer.js";

const [, , runDir, proxy, chain = "sepolia", owner = "A", port = "9333"] = process.argv;
mkdirSync(runDir, { recursive: true });
const keys = JSON.parse(readFileSync("secrets/keys.json", "utf8"));
const signer = new Signer(keys[owner].pk, chain as any, `${runDir}/signer.jsonl`, process.env.READ_ONLY === "1");
const mark = (name: string, extra: object = {}) =>
  appendFileSync(`${runDir}/markers.jsonl`, JSON.stringify({ t: Date.now() / 1000, name, ...extra }) + "\n");

// MM=1: Chromium with the MetaMask extension (driver/mm.ts) instead of the injected Lab Signer.
const MM = process.env.MM === "1";
let browser: { close: () => Promise<void> };
let ctx: BrowserContext;
if (MM) {
  const mm = await launch(runDir, proxy);
  ctx = mm.ctx; browser = ctx;
  console.log("extension", mm.extId);
  // ONBOARD=1: import the lab phrase first, so exploration starts on the home screen.
  if (process.env.ONBOARD === "1") console.log(JSON.stringify(await onboard(await onboardingTab(ctx, mm.extId), mmKeys().mnemonic)));
} else {
  const b = await chromium.launch({
    headless: false,
    proxy: { server: proxy },
    args: ["--disable-quic", "--ignore-certificate-errors", "--no-first-run", "--disable-background-networking",
      "--disable-component-update", "--disable-domain-reliability", "--disable-sync", "--metrics-recording-only",
      "--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication,CertificateTransparencyComponentUpdater"],
  });
  browser = b;
  ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: "en-US", timezoneId: "UTC" });
  await signer.install(ctx);
}
ctx.on("request", (r) => {
  const sw = r.serviceWorker() ? "sw" : "page";
  appendFileSync(`${runDir}/pw.jsonl`, JSON.stringify({ t: Date.now() / 1000, ev: "req", url: r.url(), method: r.method(), type: r.resourceType(), origin: sw, frame: r.serviceWorker() ? null : (() => { try { return r.frame().url(); } catch { return null; } })() }) + "\n");
});
ctx.on("requestfinished", async (r) => {
  const tm = r.timing();
  appendFileSync(`${runDir}/pw.jsonl`, JSON.stringify({ t: Date.now() / 1000, ev: "done", url: r.url(), method: r.method(), timing: tm }) + "\n");
});
let page: Page = ctx.pages().at(-1) ?? await ctx.newPage();
ctx.on("page", (p) => { page = p; });

const shot = async (name = "shot") => { const p = `${runDir}/${name}.png`; await page.screenshot({ path: p }); return p; };

const handlers: Record<string, (q: URLSearchParams, body: string) => Promise<any>> = {
  goto: async (q) => { await page.goto(q.get("url")!, { waitUntil: "domcontentloaded" }); return page.url(); },
  mark: async (q) => { mark(q.get("name")!); return "ok"; },
  click: async (q) => {
    const sel = q.get("sel"), text = q.get("text"), role = q.get("role"), nth = Number(q.get("nth") ?? 0);
    const loc = sel ? page.locator(sel) : role ? page.getByRole(role as any, { name: text!, exact: q.get("exact") === "1" }) : page.getByText(text!, { exact: q.get("exact") === "1" });
    await loc.nth(nth).click({ timeout: Number(q.get("timeout") ?? 15000) });
    return "clicked";
  },
  fill: async (q) => { await page.locator(q.get("sel")!).nth(Number(q.get("nth") ?? 0)).fill(q.get("value")!, { timeout: 15000 }); return "filled"; },
  press: async (q) => { await page.keyboard.press(q.get("key")!); return "ok"; },
  wait: async (q) => { await page.waitForTimeout(Number(q.get("ms"))); return "ok"; },
  waitfor: async (q) => { await page.getByText(q.get("text")!).first().waitFor({ timeout: Number(q.get("timeout") ?? 60000) }); return "ok"; },
  shot: async (q) => shot(q.get("name") ?? "shot"),
  url: async () => page.url(),
  text: async () => (await page.locator("body").innerText()).slice(0, 6000),
  eval: async (_q, body) => JSON.stringify(await page.evaluate(body)),
  buttons: async () => JSON.stringify(await page.evaluate(() => [...document.querySelectorAll("button,a,[role=button],input,[role=tab],[role=option]")].filter((e: any) => e.offsetParent).map((e: any) => `${e.tagName}|${e.getAttribute("data-testid") ?? ""}|${(e.innerText || e.value || e.getAttribute("aria-label") || e.name || e.placeholder || "").trim().slice(0, 60)}`))),
  owner: async (q) => { signer.setKey(keys[q.get("name")!].pk); return keys[q.get("name")!].address; },
  newcontext: async () => { return "unsupported"; },
  close: async () => { await browser.close(); setTimeout(() => process.exit(0), 100); return "bye"; },
};

createServer(async (req, res) => {
  const u = new URL(req.url!, "http://x");
  let body = ""; for await (const c of req) body += c;
  const h = handlers[u.pathname.slice(1)];
  try { res.end(String(h ? await h(u.searchParams, body) : "unknown")); }
  catch (e: any) { res.statusCode = 500; res.end(String(e.message).slice(0, 1500)); }
}).listen(Number(port), "127.0.0.1", () => { mark("session_start", { chain, owner }); console.log("ready"); });
handlers.frame = async (q, body) => {
  const f = page.frames().find((f) => f.url().includes(q.get("match")!));
  if (!f) return "no frame";
  return JSON.stringify(await f.evaluate(body));
};
handlers.framefill = async (q) => {
  const f = page.frames().find((f) => f.url().includes(q.get("match")!))!;
  await f.locator(q.get("sel")!).nth(Number(q.get("nth") ?? 0)).fill(q.get("value")!, { timeout: 15000 }); return "filled";
};
handlers.frameclick = async (q) => {
  const f = page.frames().find((f) => f.url().includes(q.get("match")!))!;
  const loc = q.get("sel") ? f.locator(q.get("sel")!) : f.getByText(q.get("text")!, { exact: q.get("exact") === "1" });
  await loc.nth(Number(q.get("nth") ?? 0)).click({ timeout: 15000 }); return "clicked";
};
handlers.mouse = async (q) => { await page.mouse.click(Number(q.get("x")), Number(q.get("y"))); return "ok"; };
handlers.pages = async () => JSON.stringify(ctx.pages().map((p, i) => `${i} ${p.url()}`));
handlers.use = async (q) => { page = ctx.pages()[Number(q.get("i"))]; await page.bringToFront(); return page.url(); };
// Extension pages run LavaMoat scuttling, which blocks page.evaluate; these use Playwright's own world.
handlers.aria = async () => (await page.locator("body").ariaSnapshot()).slice(0, 8000);
handlers.testids = async () => JSON.stringify(await Promise.all((await page.locator("[data-testid]:visible").all()).slice(0, 150)
  .map(async (l) => `${await l.getAttribute("data-testid")}|${(await l.innerText().catch(() => "")).trim().replace(/\s+/g, " ").slice(0, 50)}`)));
handlers.type = async (q) => { await page.keyboard.type(q.get("value")!, { delay: Number(q.get("delay") ?? 20) }); return "typed"; };
handlers.toggles = async () => JSON.stringify(await toggles(page));
handlers.frames = async () => JSON.stringify(page.frames().map((f) => f.url().slice(0, 100)));
handlers.box = async (q) => {
  const f = page.frames().find((f) => f.url().includes(q.get("match")!));
  if (!f) return "no frame";
  return JSON.stringify(await (await f.frameElement()).boundingBox());
};
