// MetaMask extension in Chromium: launch, onboarding and the extension-page helpers that the
// journey and the exploration session share. The build is pinned in README.md.
import { chromium, type BrowserContext, type Page } from "playwright";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const MM_VERSION = "13.56.0";
export const MM_DIR = resolve(process.env.MM_DIR ?? `vendor/metamask-chrome-${MM_VERSION}`);
export const PASSWORD = "lab-egress-password-1";

// MM_KEYS=secrets/metamask-explore.json tests the driver without touching the run phrase: backup and sync
// is on by default, so any run uploads its accounts and contacts and a later import restores them.
export const mmKeys = () => JSON.parse(readFileSync(process.env.MM_KEYS ?? "secrets/metamask.json", "utf8"));

// Same browser flags as the Safe driver, so the browser's own traffic matches the blank baseline.
export async function launch(runDir: string, proxy: string): Promise<{ ctx: BrowserContext; extId: string }> {
  mkdirSync(`${runDir}/profile`, { recursive: true });
  const ctx = await chromium.launchPersistentContext(`${runDir}/profile`, {
    headless: false,
    proxy: { server: proxy },
    ignoreHTTPSErrors: true,
    viewport: { width: 1440, height: 900 },
    locale: "en-US",
    timezoneId: "UTC",
    args: [`--disable-extensions-except=${MM_DIR}`, `--load-extension=${MM_DIR}`,
      "--disable-quic", "--ignore-certificate-errors", "--no-first-run", "--disable-background-networking",
      "--disable-component-update", "--disable-domain-reliability", "--disable-sync", "--metrics-recording-only",
      "--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication,CertificateTransparencyComponentUpdater"],
  });
  const log = (rec: object) => appendFileSync(`${runDir}/pw.jsonl`, JSON.stringify({ t: Date.now() / 1000, ...rec }) + "\n");
  ctx.on("request", (r) => log({ ev: "req", url: r.url(), method: r.method(), type: r.resourceType(), sw: !!r.serviceWorker() }));
  ctx.on("requestfinished", (r) => log({ ev: "done", url: r.url(), method: r.method(), timing: r.timing() }));
  const sw = ctx.serviceWorkers().find((w) => w.url().startsWith("chrome-extension://"))
    ?? await ctx.waitForEvent("serviceworker", { predicate: (w) => w.url().startsWith("chrome-extension://"), timeout: 30000 });
  const extId = new URL(sw.url()).host;
  log({ ev: "extension", id: extId, sw: sw.url() });
  return { ctx, extId };
}

// MetaMask opens home.html#onboarding/welcome by itself on install. Return that tab, or open one.
export async function onboardingTab(ctx: BrowserContext, extId: string, ms = 20000): Promise<Page> {
  const find = () => ctx.pages().find((p) => p.url().startsWith(`chrome-extension://${extId}/home.html`));
  const end = Date.now() + ms;
  while (!find() && Date.now() < end) await new Promise((r) => setTimeout(r, 250));
  const p = find() ?? await ctx.newPage();
  if (!p.url().startsWith("chrome-extension://")) await p.goto(`chrome-extension://${extId}/home.html`);
  return p;
}

// Onboarding with the lab recovery phrase. Declines usage data (MetaMetrics, pre-checked by default);
// leaves every other default as shipped. Returns the defaults seen on the way.
export async function onboard(p: Page, mnemonic: string): Promise<Record<string, unknown>> {
  const tid = (id: string) => p.locator(`[data-testid="${id}"]`).first();
  const seen: Record<string, unknown> = {};
  await tid("onboarding-import-wallet").click({ timeout: 30000 });
  await tid("onboarding-import-with-srp-button").click();
  // The phrase field splits words on key events; fill() leaves Continue disabled.
  await p.locator('[data-testid="parent-selector-onboarding-srp"] textarea').click();
  await p.keyboard.type(mnemonic, { delay: 15 });
  await tid("import-srp-confirm").click();
  await tid("create-password-new-input").fill(PASSWORD);
  await tid("create-password-confirm-input").fill(PASSWORD);
  await tid("create-password-terms").click();
  await tid("create-password-submit").click();
  await tid("passkey-maybe-later-button").click({ timeout: 30000 });
  const usage = p.getByRole("checkbox", { name: "Gather basic usage data" });
  const marketing = p.getByRole("checkbox", { name: "Marketing updates" });
  await usage.waitFor({ timeout: 30000 });
  seen.metametricsDefault = await usage.isChecked();
  seen.marketingDefault = await marketing.isChecked();
  if (await usage.isChecked()) await tid("metametrics-checkbox").click();
  if (await marketing.isChecked()) await tid("metametrics-data-collection-checkbox").click();
  seen.metametricsSet = await usage.isChecked();
  await tid("metametrics-i-agree").click();
  await tid("onboarding-complete-done").click({ timeout: 30000 });
  // "Open wallet" can stay disabled while account discovery runs; load the home page if it does.
  const home = await p.waitForURL((u) => !u.hash.includes("onboarding"), { timeout: 60000 }).then(() => true).catch(() => false);
  seen.openWalletNavigated = home;
  if (!home) await p.goto(p.url().split("#")[0]);
  await tid("account-menu-icon").waitFor({ timeout: 60000 });
  return seen;
}

// Settings toggles as the UI shows them: label (nearest paragraph) and the raw state attributes.
// isChecked() alone is not reliable on MetaMask's toggle components, so the raw attributes go to the log too.
export async function toggles(p: Page): Promise<{ label: string; on: boolean | null; raw: string }[]> {
  const out = [];
  for (const cb of await p.locator("input[type=checkbox]:visible, [role=switch]:visible, [role=checkbox]:visible").all()) {
    const label = (await cb.locator("xpath=ancestor::*[.//p][1]").locator("p").first().innerText().catch(() => "?")).trim();
    const anc = cb.locator("xpath=ancestor::*[contains(@class,'toggle')][1]");
    const raw = [await cb.getAttribute("aria-checked"), await cb.getAttribute("data-checked"), await cb.getAttribute("value"),
      await cb.isChecked().catch(() => "err"), await anc.count() ? await anc.getAttribute("class") : ""].join(" | ");
    const cls = (await anc.count()) ? (await anc.getAttribute("class")) ?? "" : "";
    const on = /--on\b|checked/.test(cls) ? true : /--off\b/.test(cls) ? false
      : (await cb.getAttribute("aria-checked")) === "true" ? true : await cb.isChecked().catch(() => null);
    out.push({ label, on, raw });
  }
  return out;
}
