// Scripted user journey through Safe{Wallet}. Every step writes a marker, so the analysis can
// attribute each captured request to the action that caused it.
//
// Usage: tsx driver/journey.ts <runDir> <proxy> <plan>
//   plan = sepolia   full journey with writes (create, receive, send, multisig, swap, custom RPC)
//   plan = mainnet   read-only pass on a public Safe (features that testnets may hide)
//   plan = baseline  blank browser, no wallet app (browser's own background traffic)
import { chromium, type Page, type Frame } from "playwright";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { Signer } from "./signer.js";

const [, , runDir, proxy, plan = "sepolia"] = process.argv;
mkdirSync(runDir, { recursive: true });
const keys = JSON.parse(readFileSync("secrets/keys.json", "utf8"));
const APP = "https://app.safe.global";
const MAINNET_SAFE = process.env.MAINNET_SAFE ?? "0x8CF60B289f8d31F737049B590b5E4285Ff0Bd1D1";
const IDLE_MS = Number(process.env.IDLE_MS ?? 180_000);
const COOKIES = process.env.COOKIES ?? "necessary"; // necessary | all

const mark = (name: string, extra: object = {}) =>
  appendFileSync(`${runDir}/markers.jsonl`, JSON.stringify({ t: Date.now() / 1000, name, ...extra }) + "\n");
const stepLog = (rec: object) => appendFileSync(`${runDir}/steps.jsonl`, JSON.stringify(rec) + "\n");

const chain = plan === "mainnet" ? "mainnet" : "sepolia";
const signer = new Signer(keys.A.pk, chain, `${runDir}/signer.jsonl`, plan === "mainnet");
const browser = await chromium.launch({
  headless: false,
  proxy: { server: proxy },
  args: ["--disable-quic", "--ignore-certificate-errors", "--no-first-run", "--disable-background-networking",
    "--disable-component-update", "--disable-domain-reliability", "--disable-sync", "--metrics-recording-only",
    "--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication,CertificateTransparencyComponentUpdater"],
});
const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, locale: "en-US", timezoneId: "UTC" });
await signer.install(ctx);
ctx.on("request", (r) => appendFileSync(`${runDir}/pw.jsonl`, JSON.stringify({
  t: Date.now() / 1000, ev: "req", url: r.url(), method: r.method(), type: r.resourceType(), sw: !!r.serviceWorker(),
}) + "\n"));
ctx.on("requestfinished", (r) => appendFileSync(`${runDir}/pw.jsonl`, JSON.stringify({
  t: Date.now() / 1000, ev: "done", url: r.url(), method: r.method(), timing: r.timing(),
}) + "\n"));
const page: Page = await ctx.newPage();
const wait = (ms: number) => page.waitForTimeout(ms);
const tid = (id: string) => page.locator(`[data-testid=${id}]`).first();
const cow = (): Frame => {
  const f = page.frames().find((f) => f.url().includes("swap.cow.fi"));
  if (!f) throw new Error("CoW widget frame not found");
  return f;
};

let safe = process.env.SAFE ?? "";
const state: Record<string, unknown> = { plan, cookies: COOKIES, owners: { A: keys.A.address, B: keys.B.address, R: keys.R.address } };

async function step(name: string, fn: () => Promise<void>, settleMs = 8000) {
  const t0 = Date.now();
  mark(name);
  let error: string | undefined;
  try { await fn(); await wait(settleMs); } catch (e: any) {
    error = String(e.message ?? e).split("\n")[0];
    await page.screenshot({ path: `${runDir}/fail-${name}.png` }).catch(() => {});
  }
  stepLog({ name, ok: !error, error, ms: Date.now() - t0 });
  console.log(`${error ? "FAIL" : "ok  "} ${name} ${((Date.now() - t0) / 1000).toFixed(0)}s ${error ?? ""}`);
  mark(`${name}:end`);
}

async function waitUntil(cond: () => boolean, ms: number, msg: string) {
  const end = Date.now() + ms;
  while (!cond()) { if (Date.now() > end) throw new Error(msg); await wait(500); }
}

async function solveTurnstile() {
  const f = cow();
  if (!(await f.getByText("Click the checkbox").count())) return;
  const ts = f.locator('iframe[src*="challenges.cloudflare.com"]').first();
  const box = await ts.boundingBox().catch(() => null);
  const holder = box ?? await f.getByText("Verify you are human").first().boundingBox();
  if (!holder) throw new Error("turnstile not located");
  await page.mouse.click(holder.x + (box ? 30 : 10), holder.y + holder.height / 2);
  await f.getByText("Click the checkbox").waitFor({ state: "detached", timeout: 30000 }).catch(() => {});
  await wait(3000);
}

async function acceptRisk() {
  const box = page.getByText("I understand the risks");
  if (await box.count()) await box.first().click();
}

async function connect() {
  const banner = page.getByRole("button", { name: COOKIES === "all" ? "Accept all" : "Save settings" });
  if (await banner.count()) await banner.first().click();
  await tid("connect-wallet-btn").click();
  await page.getByText("Lab Signer").click();
  await tid("open-account-center").waitFor({ timeout: 20000 });
}

async function switchOwner(name: "A" | "B") {
  signer.setKey(keys[name].pk);
  await page.reload({ waitUntil: "domcontentloaded" });
  await page.locator(`[data-testid=open-account-center]:has-text("${keys[name].address.slice(0, 6)}")`).waitFor({ timeout: 30000 });
}

async function proposeSend(to: string, amount: string) {
  await page.goto(`${APP}/home?safe=sep:${safe}`, { waitUntil: "domcontentloaded" });
  await tid("send-button").click({ timeout: 30000 });
  await page.locator('input[name="recipients.0.recipient"]').fill(to);
  await page.locator('input[name="recipients.0.amount"]').fill(amount);
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await tid("continue-sign-btn").waitFor({ timeout: 30000 });
  await wait(4000);
  await acceptRisk();
  await tid("continue-sign-btn").click();
  const before = signer.signed;
  await tid("combo-submit-sign").click({ timeout: 30000 });
  await waitUntil(() => signer.signed > before, 60000, "proposal not signed");
  await page.getByText("Queued").or(page.getByText("Transaction was successfully")).first().waitFor({ timeout: 30000 }).catch(() => {});
}

async function confirmAndExecute() {
  await page.goto(`${APP}/transactions/queue?safe=sep:${safe}`, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: /^(Confirm|Execute)$/ }).first().click({ timeout: 30000 });
  await tid("continue-sign-btn").waitFor({ timeout: 30000 });
  await wait(3000);
  await acceptRisk();
  await tid("continue-sign-btn").click();
  const before = signer.sentTx;
  await tid("combo-submit-execute").click({ timeout: 30000 });
  await waitUntil(() => signer.sentTx > before, 60000, "execute tx not sent");
  // Wait until the queue is empty, which means the tx was executed and indexed.
  await page.goto(`${APP}/transactions/queue?safe=sep:${safe}`, { waitUntil: "domcontentloaded" });
  await page.getByText("Queued transactions will appear here").waitFor({ timeout: 150000 });
}

async function openCow() {
  await page.goto(`${APP}/swap?safe=${chain === "mainnet" ? "eth" : "sep"}:${safe}`, { waitUntil: "domcontentloaded" });
  const cont = page.getByRole("button", { name: "Continue", exact: true });
  await cont.waitFor({ timeout: 20000 }).then(() => cont.click()).catch(() => {});
  await page.waitForFunction(() => !!document.querySelector('iframe[src*="swap.cow.fi"]'), null, { timeout: 30000 });
  await wait(10000);
  await solveTurnstile();
}

async function cowQuote(sell: string, buy: string, amount: string) {
  const f = cow();
  for (const [i, addr] of [[0, sell], [0, buy]] as const) {
    await f.getByText("Select a token").nth(i).click({ timeout: 20000 });
    await f.locator("#token-search-input").fill(addr);
    await f.locator(`div[data-address="${addr.toLowerCase()}"]`).first().click({ timeout: 20000 });
    await wait(1500);
  }
  await f.locator("input.token-amount-input, input[inputmode=decimal]").first().fill(amount);
  await wait(6000);
  await solveTurnstile();
  await wait(8000);
}

async function setCustomRpc(url: string) {
  await page.goto(`${APP}/settings/environment-variables?safe=sep:${safe}`, { waitUntil: "domcontentloaded" });
  await page.locator('input[name="rpc"]').fill(url, { timeout: 20000 });
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await wait(2000);
  await page.goto(`${APP}/home?safe=sep:${safe}`, { waitUntil: "domcontentloaded" });
}

function external(kind: "eth" | "weth", amount: string) {
  execFileSync("npx", ["tsx", "driver/external.ts", kind, safe, amount], { stdio: "inherit" });
}

const WETH_SEP = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14";
const COW_SEP = "0x0625aFB445C3B6B7B929342a04A22599fd5dBB59";
const WETH_MAIN = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const COW_MAIN = "0xDEf1CA1fb7FBcDC777520aa7f396b4E015F497aB";

if (plan === "baseline") {
  await step("baseline_blank", async () => { await page.goto("about:blank"); await wait(IDLE_MS); }, 0);
} else if (plan === "sepolia") {
  await step("cold_load", async () => { await page.goto(`${APP}/welcome/accounts`, { waitUntil: "domcontentloaded" }); }, 15000);
  await step("connect_wallet", connect, 10000);
  await step("create_safe", async () => {
    await tid("open-add-accounts-chooser-button").click();
    await tid("add-accounts-create-new").click();
    await page.locator('input[name="name"]').fill(`Lab Safe ${new Date().toISOString().slice(0, 16)}`);
    await tid("next-btn").click();
    await tid("add-new-signer").click();
    await page.locator('input[name="owners.1.address"]').fill(keys.B.address);
    await wait(2500);
    await tid("threshold-selector").click();
    await page.locator("[data-testid=threshold-item]").nth(1).click();
    await tid("next-btn").click();
    await tid("review-step-next-btn").click({ timeout: 30000 });
    await page.waitForURL(/safe=sep:0x/, { timeout: 180000 });
    safe = new URL(page.url()).searchParams.get("safe")!.split(":")[1];
    state.safe = safe;
    const go = tid("cf-creation-lets-go-btn");
    await go.waitFor({ timeout: 15000 }).then(() => go.click()).catch(() => {});
  }, 15000);
  await step("idle_empty", async () => { await wait(60000); }, 0);
  await step("receive_eth", async () => { external("eth", "0.01"); }, 45000);
  await step("receive_token", async () => { external("weth", "0.005"); }, 45000);
  await step("view_assets", async () => { await page.goto(`${APP}/balances?safe=sep:${safe}`, { waitUntil: "domcontentloaded" }); }, 12000);
  await step("view_history", async () => { await page.goto(`${APP}/transactions/history?safe=sep:${safe}`, { waitUntil: "domcontentloaded" }); }, 12000);
  await step("send_propose_A", async () => { await proposeSend(keys.R.address, "0.002"); }, 8000);
  await step("send_confirm_execute_B", async () => { await switchOwner("B"); await confirmAndExecute(); }, 10000);
  await step("swap_quote", async () => { await switchOwner("A"); await openCow(); await cowQuote(WETH_SEP, COW_SEP, "0.002"); }, 5000);
  await step("swap_place_A", async () => {
    const f = cow();
    await solveTurnstile();
    await f.getByRole("button", { name: /Swap$/ }).last().click({ timeout: 20000 });
    await f.getByRole("button", { name: "Confirm Swap" }).click({ timeout: 20000 });
    await tid("continue-sign-btn").waitFor({ timeout: 30000 });
    await wait(3000);
    await acceptRisk();
    await tid("continue-sign-btn").click();
    const before = signer.signed;
    await tid("combo-submit-sign").click({ timeout: 30000 });
    await waitUntil(() => signer.signed > before, 60000, "swap proposal not signed");
  }, 10000);
  await step("swap_execute_B", async () => { await switchOwner("B"); await confirmAndExecute(); }, 20000);
  await step("idle_home", async () => {
    await switchOwner("A");
    await page.goto(`${APP}/home?safe=sep:${safe}`, { waitUntil: "domcontentloaded" });
    await wait(IDLE_MS);
  }, 0);
  await step("custom_rpc_set", async () => { await setCustomRpc(process.env.CUSTOM_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com"); }, 15000);
  await step("custom_rpc_send_review", async () => {
    await tid("send-button").click({ timeout: 30000 });
    await page.locator('input[name="recipients.0.recipient"]').fill(keys.R.address);
    await page.locator('input[name="recipients.0.amount"]').fill("0.001");
    await page.getByRole("button", { name: "Next", exact: true }).click();
    await tid("continue-sign-btn").waitFor({ timeout: 30000 });
  }, 10000);
  await step("custom_rpc_idle", async () => {
    await page.goto(`${APP}/home?safe=sep:${safe}`, { waitUntil: "domcontentloaded" });
    await wait(60000);
  }, 0);
} else if (plan === "mainnet") {
  safe = MAINNET_SAFE; state.safe = safe;
  await step("cold_load", async () => { await page.goto(`${APP}/welcome/accounts`, { waitUntil: "domcontentloaded" }); }, 15000);
  await step("connect_wallet", connect, 10000);
  await step("open_safe_home", async () => { await page.goto(`${APP}/home?safe=eth:${safe}`, { waitUntil: "domcontentloaded" }); }, 20000);
  await step("view_assets", async () => { await page.goto(`${APP}/balances?safe=eth:${safe}`, { waitUntil: "domcontentloaded" }); }, 15000);
  await step("view_positions", async () => { await page.goto(`${APP}/balances/positions?safe=eth:${safe}`, { waitUntil: "domcontentloaded" }); }, 15000);
  await step("view_history", async () => { await page.goto(`${APP}/transactions/history?safe=eth:${safe}`, { waitUntil: "domcontentloaded" }); }, 15000);
  await step("view_apps", async () => { await page.goto(`${APP}/apps?safe=eth:${safe}`, { waitUntil: "domcontentloaded" }); }, 15000);
  await step("swap_quote", async () => { await openCow(); await cowQuote(WETH_MAIN, COW_MAIN, "1"); }, 5000);
  await step("idle_home", async () => {
    await page.goto(`${APP}/home?safe=eth:${safe}`, { waitUntil: "domcontentloaded" });
    await wait(IDLE_MS);
  }, 0);
}

writeFileSync(`${runDir}/state.json`, JSON.stringify(state, null, 2));
mark("journey_end");
await browser.close();
