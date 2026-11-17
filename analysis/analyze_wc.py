# WalletChan run: attribute each flow to the wallet, a visited page or the browser, assign step,
# operator and tier, and search for the known values. Writes <run>/analysis_wc.json.
# Usage: python3 -I analysis/analyze_wc.py <run> <keys.json> [extra known values as name=value ...]
import json, sys, re
from collections import Counter, defaultdict

run, keyfile = sys.argv[1], sys.argv[2]
keys = json.load(open(keyfile))
marks = [json.loads(l) for l in open(f"{run}/markers.jsonl")]

# Known values. Derived addresses #2..#4 only ever appear because seed import looks them up.
known = {"A": keys["A"]["address"], "B": keys["B"]["address"]}
for kv in sys.argv[3:]:
    k, v = kv.split("=", 1); known[k] = v
needles = {k: v.lower().removeprefix("0x") for k, v in known.items()}

# Hosts the wallet reaches without an Origin header (images, GETs from the background worker).
WALLET_NO_ORIGIN = re.compile(r"(^|\.)walletchan\.eth\.sh$|^eth\.sh$|coingecko\.com$|^t1\.gstatic\.com$|\.ipfs\.localhost$|\.eth\.limo$")
BROWSER = re.compile(r"google\.com$|googleapis\.com$|^clients2\.google|android\.clients")

OPERATORS = [
    (r"walletchan\.eth\.sh$", "WalletChan"), (r"^eth\.sh$", "eth.sh (WalletChan dev)"),
    (r"drpc\.org$", "dRPC"), (r"publicnode\.com$", "PublicNode (user-set RPC)"),
    (r"coingecko\.com$", "CoinGecko"), (r"gstatic\.com$", "Google"), (r"walletconnect\.org$", "WalletConnect (Reown)"),
    (r"alchemy\.com$", "Alchemy"), (r"binance\.org$", "BNB Chain"), (r"arbitrum\.io$", "Arbitrum"),
    (r"optimism\.io$", "OP Labs"), (r"avax\.network$", "Avalanche"), (r"megaeth\.com$", "MegaETH"),
    (r"abs\.xyz$", "Abstract"), (r"berachain\.com$", "Berachain"), (r"hyperliquid\.xyz$", "Hyperliquid"),
    (r"linea\.build$", "Linea"), (r"monad\.xyz$", "Monad"), (r"inkonchain\.com$", "Ink"), (r"plasma\.to$", "Plasma"),
    (r"robinhood\.com$", "Robinhood"), (r"unichain\.org$", "Unichain"), (r"zksync\.io$", "ZKsync"),
    (r"tempo\.xyz$", "Tempo"), (r"eth\.limo$", "eth.limo"), (r"localhost$", "local (IPFS probe)"),
]
def operator(h):
    return next((n for p, n in OPERATORS if re.search(p, h)), h)

def step(t):
    cur = "install"
    for m in marks:
        if m["t"] <= t: cur = m["name"]
    return cur

INTENT = re.compile(r"/api/swap/(price|quote)|/api/bridge/quote|eth_sendRawTransaction|eth_estimateGas|eth_simulateV1|debug_traceCall|eth_createAccessList|eth_fillTransaction|/api/clearsigning|/api/labels/")

rows = []
for line in open(f"{run}/flows.jsonl"):
    r = json.loads(line)
    if r["kind"] == "ws": continue
    h = dict((k.lower(), v) for k, v in r.get("req_headers", []))
    src = (h.get("origin", "") + " " + h.get("referer", "")).strip()
    host = r["host"]
    if "chrome-extension://" in src or (not src and WALLET_NO_ORIGIN.search(host)): who = "wallet"
    elif BROWSER.search(host) and not src: who = "browser"
    else: who = "page"
    blob = (r["url"] + " " + r["req_body"].get("text", "")).lower()
    found = sorted(k for k, n in needles.items() if n and n in blob)
    addr = any(k in found for k in known if re.fullmatch(r"[A-Z]|D\d", k))
    body = r["req_body"].get("text", "")
    m = re.search(r'"method":"([a-zA-Z_0-9]+)"', body)
    method = m.group(1) if m else None
    if method == "eth_call" and "82ad56cb" in body: method = "multicall (aggregate3)"
    intent = bool(INTENT.search(r["url"] + " " + (method or "")) and (addr or "B" in found or "labels" in r["url"]))
    tier = "intent" if intent else "address" if addr else "telemetry" if "walletconnect" in host else "free"
    t = r.get("t_start") or r.get("t")
    rows.append(dict(t=t, step=step(t), who=who, host=host, op=operator(host), method=r["method"], rpc=method,
                     path=r["url"].split("?")[0][:120], status=r["status"], found=found, tier=tier))

w = [x for x in rows if x["who"] == "wallet"]
out = {
    "run": run, "known": known,
    "totals": {"all": len(rows), "wallet": len(w), "page": sum(x["who"] == "page" for x in rows), "browser": sum(x["who"] == "browser" for x in rows)},
    "tiers": Counter(x["tier"] for x in w),
    "operators": sorted(([op, sum(1 for x in w if x["op"] == op), sum(1 for x in w if x["op"] == op and x["tier"] in ("address", "intent"))]
                         for op in {x["op"] for x in w}), key=lambda r: -r[1]),
    "ops_with_address": sorted({x["op"] for x in w if x["tier"] in ("address", "intent")}),
    "steps": defaultdict(dict),
    "values": {k: Counter(x["op"] for x in w if k in x["found"]) for k in known},
}
for x in w:
    s = out["steps"][x["step"]]
    s.setdefault("n", 0); s["n"] += 1
    s.setdefault("addr", 0); s["addr"] += x["tier"] in ("address", "intent")
    s.setdefault("ops", Counter())[x["op"]] += 1
json.dump({**out, "rows": w}, open(f"{run}/analysis_wc.json", "w"), indent=1, default=dict)
print(json.dumps({k: out[k] for k in ("totals", "tiers", "ops_with_address")}, default=dict, indent=1))
for op, n, a in out["operators"]: print(f"{n:5} {a:5}  {op}")
for k, c in out["values"].items(): print(k, dict(c))
