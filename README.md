# wallet-egress-lab

This harness records every network request that a web wallet makes during a
scripted user session. It then classifies each request by who receives it and
what it carries, and writes one self-contained HTML report.

The first target is Safe{Wallet} (app.safe.global). The capture, analysis and
report do not depend on Safe. Only `driver/journey.ts` holds Safe-specific steps.

```
npm install && npx playwright install chromium
uv tool install mitmproxy            # mitmdump on PATH; install Xvfb from your distro
npx tsx driver/keys.ts               # create secrets/keys.json (owners A, B, outside account R)
FUNDER_KEY=0x... npx tsx driver/keys.ts fund   # sends about 0.4 Sepolia ETH to A, B, R

scripts/run.sh baseline              # blank browser: the browser's own traffic
scripts/run.sh sepolia               # full journey with writes, about 20 min
MITM_PORT=8083 scripts/run.sh mainnet  # read-only pass on a public Safe

python3 -I analysis/analyze.py runs/<sepolia-run> --baseline runs/<baseline-run>
python3 -I analysis/analyze.py runs/<mainnet-run> --baseline runs/<baseline-run>
python3 -I analysis/report.py --sepolia runs/<sepolia-run> --mainnet runs/<mainnet-run> --site docs
python3 -I analysis/verify.py runs/<sepolia-run> runs/<baseline-run>   # recount headline numbers from the raw capture

# Measured latency: run the journey through Tor (HTTPTunnelPort) and on clearnet, then pass both
UPSTREAM=http://127.0.0.1:9080 scripts/run.sh sepolia sepolia-tor
scripts/run.sh sepolia sepolia-clear
python3 -I analysis/report.py --sepolia runs/<sepolia-run> --mainnet runs/<mainnet-run> --tor runs/<tor-run> --clear runs/<clear-run> --site docs
```

## How a run works

| Part | File | What it does |
|---|---|---|
| Proxy | `capture/record.py` | mitmproxy addon. Writes one JSON line per HTTP flow (headers, bodies, timings, connection ids) and per WebSocket message to `flows.jsonl`. |
| Browser | `driver/journey.ts` | Chromium (Playwright), headed under Xvfb, fresh profile, QUIC off, all traffic through the proxy. Writes a marker before and after each step to `markers.jsonl`. |
| Signer | `driver/signer.ts` | Injected EIP-1193 provider, announced over EIP-6963 as "Lab Signer". Keys and the signer's RPC stay in Node, outside the proxied browser. The capture therefore holds only wallet-app traffic. |
| Outside party | `driver/external.ts` | Account R sends ETH or WETH to the Safe, to simulate "receive". |
| Analysis | `analysis/analyze.py` | Assigns each request to a step, an operator and a service category. Searches URLs, headers and bodies for known values (Safe address, owners, counterparty, safeTxHash, CoW order ids, analytics client ids). Assigns a tier. Writes `analysis.json`. |
| Report | `analysis/report.py`, `analysis/template.html`, `analysis/index.html` | One template, two pages per run under `docs/runs/<run>/`: `index.html`, the brief (thesis, fix list, latency, timeline, appendix collapsed), and `full.html`, the same page with the appendix open. `docs/index.html` lists all runs. |
| Exploration | `driver/session.ts`, `bin-lab.sh` | Long-running browser with an HTTP control port. Use it to find selectors for new steps. |

## Tiers

| Tier | Meaning |
|---|---|
| Address-free | No address or client id. The server still sees the IP address and timing. |
| Telemetry and fingerprint | Analytics, error reports, feature flags, bot checks. A client or device id, no address. |
| Address-linked read | Carries the Safe address or an owner address. |
| Intent before chain | Shows a pending action (recipient, amount, calldata, quote, signature) before it is on chain. |

## Sepolia journey

Open app, connect signer, create a 2-of-2 Safe (owners A and B), idle, receive
ETH, receive WETH, view assets and history, send ETH (A proposes, B confirms
and executes), swap WETH to COW in the CoW widget (A places the order, B
executes), idle on the home page, set a custom RPC, review a send, idle.

Variables: `IDLE_MS` (idle length), `COOKIES=necessary|all` (cookie banner
choice), `CUSTOM_RPC`, `SAFE` (reuse a Safe), `MAINNET_SAFE`.

## MetaMask

`driver/metamask.ts` runs the same journey in the MetaMask extension. Capture, analysis and report are
shared; `driver/mm.ts` holds the launch, onboarding and settings helpers.

Pinned build: MetaMask 13.56.0, `metamask-chrome-13.56.0.zip` from
https://github.com/MetaMask/metamask-extension/releases/tag/v13.56.0

```
SHA-256 7618eda1fba0ca2068054b69faddb5c511dbb49e7d8e3ad411a8ab90551c7159
```

The SHA-256 matches the release's `SHA256SUMS`, and the Sigstore bundle verifies against
`MetaMask/metamask-extension` (`uvx sigstore verify github --bundle <zip>.sigstore.json --repository MetaMask/metamask-extension <zip>`).

```
mkdir -p vendor/dl && cd vendor/dl
gh release download v13.56.0 -R MetaMask/metamask-extension -p 'metamask-chrome-13.56.0.zip' -p SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS && cd .. && unzip -q dl/metamask-chrome-13.56.0.zip -d metamask-chrome-13.56.0 && cd ..

npx tsx driver/mm-keys.ts            # create secrets/metamask.json (lab recovery phrase, accounts A and B)
FUNDER_KEY=0x... npx tsx driver/mm-keys.ts fund

DRIVER=metamask scripts/run.sh baseline mm-baseline   # extension loaded, never opened
DRIVER=metamask scripts/run.sh sepolia mm-sepolia     # full journey, defaults on
MM=1 ONBOARD=1 ./bin-lab.sh start runs/explore-mm      # exploration session on the home screen
```

| Safe step | MetaMask step |
|---|---|
| cold_load, connect_wallet | cold_load (extension opens its onboarding tab), connect_wallet (import the lab phrase, decline usage data, open the wallet) |
| (none) | select_sepolia: turn on "Show test networks", filter the home screen to Sepolia |
| create_safe | add_accounts: add account B, add R as a contact |
| idle_empty, receive_eth, receive_token | same |
| view_assets, view_history | view_assets (NFTs, Tokens, import WETH), view_history (Activity) |
| send_propose_A, send_confirm_execute_B | send_eth: A sends to B and confirms. No multisig equivalent |
| swap_quote, swap_place_A, swap_execute_B | swap_quote, swap_place on swap.cow.fi through the extension connect flow (MetaMask Swaps lists no testnets) |
| idle_home, custom_rpc_set, custom_rpc_send_review, custom_rpc_idle | same |

- Use a recovery phrase only once. Backup and sync is on by default, so a run uploads its accounts and
  contacts, and a later import of the same phrase restores them. The swap also leaves A with an EIP-7702
  delegation and a WETH allowance. Rotate `secrets/metamask.json` before each journey run, and test the
  driver with `MM_KEYS=secrets/metamask-explore.json`.
- Extension pages run LavaMoat scuttling, which blocks `page.evaluate`. Use locators.

## Notes

- `runs/` and `secrets/` are not committed. Runs hold addresses, signatures and
  full request bodies.
- The CoW widget shows a Cloudflare Turnstile check. The driver clicks it. If
  Cloudflare changes the check, the swap steps can fail; the run continues and
  `steps.jsonl` records the failure.
- The browser's own Google traffic (component updates, GCM) is removed with the
  baseline run.
