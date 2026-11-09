// Scripted user journey through the MetaMask extension (pinned build, see README.md). Every step writes
// a marker, so the analysis can attribute each captured request to the action that caused it.
// Step names follow driver/journey.ts where a step has a Safe equivalent, so the two timelines line up.
// The multisig steps (B confirms and executes) have no MetaMask equivalent and are not run.
//
// Usage: tsx driver/metamask.ts <runDir> <proxy> <plan>
//   plan = baseline  extension loaded, never opened (its onboarding tab is closed as soon as it appears)
//   plan = onboard   onboarding and wallet setup only, then idle on the home screen
//   plan = sepolia   full journey
import { type Page } from "playwright";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createPublicClient, http } from "viem";
import { sepolia } from "viem/chains";
import { launch, onboard, onboardingTab, toggles, mmKeys, MM_VERSION } from "./mm.js";

const [, , runDir, proxy, plan = "sepolia"] = process.argv;
mkdirSync(runDir, { recursive: true });
const IDLE_MS = Number(process.env.IDLE_MS ?? 180_000);
const CUSTOM_RPC = process.env.CUSTOM_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com";
const COW_URL = "https://swap.cow.fi/#/11155111/swap/WETH/COW";
const WETH_SEP = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14";
const COW_SEP = "0x0625aFB445C3B6B7B929342a04A22599fd5dBB59";

const mm = mmKeys();
const R = JSON.parse(readFileSync("secrets/keys.json", "utf8")).R.address as string;
// Chain checks run in Node, outside the proxied browser, so they do not enter the capture.
const chain = createPublicClient({ chain: sepolia, transport: http(process.env.SIGNER_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com") });

const mark = (name: string, extra: object = {}) =>
  appendFileSync(`${runDir}/markers.jsonl`, JSON.stringify({ t: Date.now() / 1000, name, ...extra }) + "\n");
const stepLog = (rec: object) => appendFileSync(`${runDir}/steps.jsonl`, JSON.stringify(rec) + "\n");

mark("launch");
const { ctx, extId } = await launch(runDir, proxy);
const EXT = `chrome-extension://${extId}`;
const state: Record<string, any> = {
  wallet: "MetaMask", version: MM_VERSION, plan, extId, idleMs: IDLE_MS,
  accounts: { A: mm.A.address, B: mm.B.address, R }, tokens: { WETH: WETH_SEP, COW: COW_SEP }, notes: [],
};
let page: Page = ctx.pages()[0] ?? await ctx.newPage(); // the page that fail screenshots are taken from
let wallet: Page; // the extension's full-screen tab
let dapp: Page | undefined;
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const tid = (p: Page, id: string) => p.locator(`[data-testid="${id}"]`).first();

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

async function home() {
  page = wallet;
  await wallet.bringToFront();
  await wallet.goto(`${EXT}/home.html#/`);
  await tid(wallet, "account-menu-icon").waitFor({ timeout: 30000 });
}

// Pending dapp requests. MetaMask opens notification.html in a popup window, which Playwright does not
// always see; opening notification.html in the wallet tab shows the same pending approval.
async function approve(ids: string[], ms = 30000) {
  const popup = await ctx.waitForEvent("page", { predicate: (p) => p.url().includes("notification.html"), timeout: 5000 }).catch(() => null);
  const p = popup ?? wallet;
  page = p;
  await p.bringToFront();
  // The request can reach the extension after the page has loaded; reload until it shows.
  for (let i = 0; !popup; i++) {
    await wallet.goto(`${EXT}/notification.html`);
    if (await tid(p, ids[0]).waitFor({ timeout: 10000 }).then(() => true).catch(() => false)) break;
    if (i === 3) throw new Error(`no pending approval (${ids[0]})`);
  }
  for (const id of ids) await tid(p, id).click({ timeout: ms });
}

async function nonce() { return chain.getTransactionCount({ address: mm.A.address, blockTag: "latest" }); }
async function waitNonce(above: number, ms: number) {
  const end = Date.now() + ms;
  while ((await nonce()) <= above) { if (Date.now() > end) throw new Error("tx not mined"); await wait(3000); }
}

function external(kind: "eth" | "weth", amount: string) {
  execFileSync("npx", ["tsx", "driver/external.ts", kind, mm.A.address, amount], { stdio: "inherit" });
}

async function solveTurnstile(p: Page) {
  const gate = tid(p, "trade-form-blank-button").filter({ hasText: "Click the checkbox" });
  for (let i = 0; i < 3 && (await gate.count()); i++) {
    const ts = p.frames().find((fr) => fr.url().includes("challenges.cloudflare.com"));
    let box = ts ? await (await ts.frameElement()).boundingBox().catch(() => null) : null;
    if (!box) {
      // The widget sits directly above the "Click the checkbox" button.
      const b = await gate.boundingBox({ timeout: 5000 });
      if (!b) throw new Error("turnstile not located");
      box = { x: b.x, y: b.y - 80, width: b.width, height: 65 };
    }
    await p.mouse.click(box.x + 21, box.y + box.height / 2);
    await gate.waitFor({ state: "detached", timeout: 20000 }).catch(() => {});
  }
  if (await gate.count()) throw new Error("turnstile not solved");
}

async function openSend(to: "Account 2" | string, amount: string) {
  await tid(wallet, "eth-overview-send").click({ timeout: 30000 });
  await tid(wallet, "token-asset-0xaa36a7-SepoliaETH").click({ timeout: 30000 });
  await tid(wallet, "open-recipient-modal-btn").click();
  await wallet.locator(`[role=dialog] p:text-is("${to}")`).click({ timeout: 15000 });
  await tid(wallet, "send-amount-input").fill(amount);
  await tid(wallet, "send-continue-button").click({ timeout: 30000 }); // enabled once the balance has loaded
  await tid(wallet, "confirm-footer-button").waitFor({ timeout: 30000 });
}

async function setup() {
  await step("cold_load", async () => {
    wallet = await onboardingTab(ctx, extId, 30000);
    page = wallet;
  }, 15000);
  await step("connect_wallet", async () => {
    state.onboarding = await onboard(wallet, mm.mnemonic);
    if (!state.onboarding.openWalletNavigated) state.notes.push("'Open wallet' stayed disabled for 60 s after onboarding; the driver loaded home.html");
  }, 10000);
  // Sepolia is hidden until "Show test networks" is on (Networks page). Then filter the home screen to it.
  await step("select_sepolia", async () => {
    await wallet.goto(`${EXT}/home.html#/networks`);
    await tid(wallet, "networks-page-show-test-networks").waitFor({ state: "attached", timeout: 30000 });
    state.defaults = { showTestNetworks: (await toggles(wallet)).find((t) => t.label === "Show test networks")?.on };
    await wallet.locator('.toggle-button:has([data-testid="networks-page-show-test-networks"])').click();
    await tid(wallet, "network-list-item-eip155:11155111").waitFor({ timeout: 15000 });
    await home();
    await tid(wallet, "sort-by-networks").click();
    await wallet.locator('[role=dialog] p:text-is("Sepolia")').click({ timeout: 15000 });
    await tid(wallet, "sort-by-networks").filter({ hasText: "Sepolia" }).waitFor({ timeout: 15000 });
  }, 10000);
  // Safe step create_safe has no equivalent. Add account B (index 1) and the outside account R as a contact.
  // R stays outside the wallet: imported, it would be polled with A and become one of the user's accounts.
  await step("add_accounts", async () => {
    await tid(wallet, "account-menu-icon").click();
    await tid(wallet, "add-multichain-account-button").waitFor({ timeout: 15000 });
    if (await wallet.locator(`[data-testid="multichain-account-cell-name-Account 2"]`).count()) {
      state.notes.push("Account 2 already present after import (restored by backup and sync): this phrase was used before");
    } else {
      await tid(wallet, "add-multichain-account-button").click();
      await wallet.locator(`[data-testid="multichain-account-cell-name-Account 2"]`).waitFor({ timeout: 30000 });
    }
    const shown = await wallet.locator('[data-testid^="multichain-account-cell-entropy:"][data-testid$="/1"]').innerText();
    if (!shown.includes(mm.B.address.slice(0, 7))) throw new Error(`Account 2 is not B: ${shown}`);
    await wallet.goto(`${EXT}/home.html#/contacts`);
    await tid(wallet, "contacts-add-contact-button").waitFor({ timeout: 15000 });
    if (await tid(wallet, "contact-list-item").count()) {
      state.notes.push("Contact R already present after import (restored by backup and sync): this phrase was used before");
    } else {
      await tid(wallet, "contacts-add-contact-button").click();
      await wallet.locator('input[placeholder="Add alias"]').fill("R outside", { timeout: 15000 });
      await wallet.locator('input[placeholder^="Enter public address"]').fill(R);
      await tid(wallet, "page-container-footer-next").click({ timeout: 15000 });
      await tid(wallet, "contact-list-item").waitFor({ timeout: 15000 });
    }
    await home();
  }, 8000);
}

if (plan === "baseline") {
  await step("baseline_extension", async () => {
    const tab = await onboardingTab(ctx, extId);
    state.onboardingTabClosedAt = Date.now() / 1000;
    page = ctx.pages().find((p) => p !== tab) ?? await ctx.newPage();
    await tab.close();
    await page.goto("about:blank");
    await wait(IDLE_MS);
  }, 0);
} else if (plan === "onboard") {
  await setup();
  await step("idle_home", async () => { await home(); await wait(IDLE_MS); }, 0);
} else if (plan === "sepolia") {
  await setup();
  await step("idle_empty", async () => { await home(); await wait(60000); }, 0);
  await step("receive_eth", async () => { external("eth", "0.01"); }, 45000);
  await step("receive_token", async () => { external("weth", "0.005"); }, 45000);
  // Tokens and NFTs tabs, then import WETH (Manage tokens > Add a custom token).
  await step("view_assets", async () => {
    await home();
    await tid(wallet, "account-overview__nfts-tab").click();
    await wait(5000);
    await tid(wallet, "account-overview__asset-tab").click();
    await wallet.goto(`${EXT}/home.html#/custom-token-import`);
    await tid(wallet, "custom-token-import-address-input").fill(WETH_SEP, { timeout: 15000 });
    const symbol = wallet.getByRole("textbox", { name: "Token symbol" });
    for (let i = 0; i < 30 && (await symbol.inputValue().catch(() => "")) !== "WETH"; i++) await wait(500);
    await tid(wallet, "custom-token-import-submit-button").click({ timeout: 15000 });
    await wallet.getByText("“WETH” was successfully added!").waitFor({ timeout: 15000 });
    await home();
  }, 12000);
  await step("view_history", async () => { await tid(wallet, "bottom-nav-activity").click(); await tid(wallet, "activity-list-item").first().waitFor({ timeout: 30000 }); }, 12000);
  // Safe: send_propose_A + send_confirm_execute_B. MetaMask: A sends to B and confirms.
  await step("send_eth", async () => {
    await home();
    const n = await nonce();
    await openSend("Account 2", "0.002");
    await tid(wallet, "confirm-footer-button").click();
    await waitNonce(n, 120000);
    await tid(wallet, "bottom-nav-activity").click();
  }, 10000);
  // MetaMask Swaps lists no testnets (13.56), so the swap runs on the CoW Swap dapp through the
  // extension's connect flow. CoW sends approve + order as one batch; MetaMask offers a smart-account
  // (EIP-7702) upgrade for it by default, which the default run accepts.
  state.notes.push("MetaMask Swaps has no Sepolia: its network picker lists mainnets only. Swap done on swap.cow.fi via the extension connect flow.");
  await step("swap_quote", async () => {
    dapp = await ctx.newPage();
    page = dapp;
    await dapp.goto(COW_URL, { waitUntil: "domcontentloaded" });
    await dapp.getByRole("button", { name: "Connect wallet", exact: true }).first().click({ timeout: 30000 });
    await dapp.getByText("MetaMask", { exact: true }).first().click({ timeout: 15000 });
    await approve(["confirm-btn", "page-container-footer-next"]);
    page = dapp;
    await dapp.bringToFront();
    await dapp.getByRole("button", { name: new RegExp(`^${mm.A.address.slice(0, 6)}`, "i") }).waitFor({ timeout: 30000 });
    await dapp.getByRole("button", { name: "Not now" }).click({ timeout: 5000 }).catch(() => {});
    await dapp.getByRole("button", { name: "Swap now" }).click({ timeout: 10000 }).catch(() => {});
    await tid(dapp, "token-amount-input").first().waitFor({ timeout: 30000 });
    await wait(5000);
    await solveTurnstile(dapp);
    await tid(dapp, "token-amount-input").first().fill("0.002");
    await tid(dapp, "trade-form-blank-button").filter({ hasText: /Swap/ }).waitFor({ timeout: 60000 });
  }, 5000);
  // Safe: swap_place_A + swap_execute_B. MetaMask: A approves and places the order in one confirmation.
  await step("swap_place", async () => {
    const d = dapp!;
    await tid(d, "trade-form-blank-button").click({ timeout: 20000 });
    await d.getByRole("button", { name: "Confirm Swap" }).click({ timeout: 20000 });
    await approve(["confirm-footer-button"], 60000);
    page = d;
    await d.bringToFront();
    await d.getByText(/Swap complete|Order filled/).first().waitFor({ timeout: 240000 });
  }, 20000);
  await step("idle_home", async () => { await home(); await wait(IDLE_MS); }, 0);
  // Settings > Networks > Sepolia > Edit > Add RPC URL. The new URL becomes Sepolia's default RPC.
  await step("custom_rpc_set", async () => {
    await wallet.goto(`${EXT}/home.html#/networks`);
    await tid(wallet, "network-list-item-options-button-eip155:11155111").click({ timeout: 30000 });
    await wallet.getByRole("button", { name: "Edit", exact: true }).click();
    await tid(wallet, "test-add-rpc-drop-down").click({ timeout: 15000 });
    await wallet.getByRole("button", { name: "Add RPC URL" }).click();
    await tid(wallet, "rpc-url-input-test").fill(CUSTOM_RPC, { timeout: 15000 });
    await tid(wallet, "page-container-footer-next").click({ timeout: 15000 }); // Add URL
    await tid(wallet, "test-add-rpc-drop-down").filter({ hasText: new URL(CUSTOM_RPC).host }).waitFor({ timeout: 15000 });
    await tid(wallet, "page-container-footer-next").click(); // Save
    await home();
  }, 15000);
  await step("custom_rpc_send_review", async () => { await openSend("Account 2", "0.001"); }, 10000);
  await step("custom_rpc_idle", async () => {
    await tid(wallet, "confirm-footer-cancel-button").click({ timeout: 10000 }).catch(() => {});
    await home();
    await wait(60000);
  }, 0);
}

// Tx hashes for the identifier search, read from a block explorer in Node (outside the capture).
if (plan === "sepolia") {
  state.txs = await fetch(`https://eth-sepolia.blockscout.com/api/v2/addresses/${mm.A.address}/transactions`)
    .then((r) => r.json()).then((j: any) => j.items.map((t: any) => ({ hash: t.hash, from: t.from.hash, to: t.to?.hash, method: t.method })))
    .catch((e) => String(e));
}
writeFileSync(`${runDir}/state.json`, JSON.stringify(state, null, 2));
mark("journey_end");
await ctx.close();
