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
```

## How a run works

| Part | File | What it does |
|---|---|---|
| Proxy | `capture/record.py` | mitmproxy addon. Writes one JSON line per HTTP flow (headers, bodies, timings, connection ids) and per WebSocket message to `flows.jsonl`. |
| Browser | `driver/journey.ts` | Chromium (Playwright), headed under Xvfb, fresh profile, QUIC off, all traffic through the proxy. Writes a marker before and after each step to `markers.jsonl`. |
| Signer | `driver/signer.ts` | Injected EIP-1193 provider, announced over EIP-6963 as "Lab Signer". Keys and the signer's RPC stay in Node, outside the proxied browser. The capture therefore holds only wallet-app traffic. |
| Outside party | `driver/external.ts` | Account R sends ETH or WETH to the Safe, to simulate "receive". |
| Analysis | `analysis/analyze.py` | Assigns each request to a step, an operator and a service category. Searches URLs, headers and bodies for known values (Safe address, owners, counterparty, safeTxHash, CoW order ids, analytics client ids). Assigns a tier. Writes `analysis.json`. |
| Report | `analysis/report.py`, `analysis/template.html`, `analysis/index.html` | One self-contained HTML report per run under `docs/runs/<run>/`, and `docs/index.html`, which lists all runs. `--out file.html` writes a single report instead. |
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

## Notes

- `runs/` and `secrets/` are not committed. Runs hold addresses, signatures and
  full request bodies.
- The CoW widget shows a Cloudflare Turnstile check. The driver clicks it. If
  Cloudflare changes the check, the swap steps can fail; the run continues and
  `steps.jsonl` records the failure.
- The browser's own Google traffic (component updates, GCM) is removed with the
  baseline run.
