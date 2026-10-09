"""Classify every captured request of a run and write <run>/analysis.json.

Usage: python3 -I analysis/analyze.py <runDir> [--baseline <baselineRunDir>]

Per request it records: step (from markers), operator, service category, the identifiers it
carries (found by searching for values we know: Safe address, owners, counterparty, tx hashes,
client IDs), a sensitivity tier, wire bytes and latency.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# --- operators -------------------------------------------------------------------------------
OPERATORS = [
    ("safe.global", "Safe"),
    ("cow.fi", "CoW Protocol"),
    ("batch.exchange", "CoW Protocol"),
    ("google-analytics.com", "Google Analytics"),
    ("googletagmanager.com", "Google Analytics"),
    ("walletconnect.org", "WalletConnect (Reown)"),
    ("walletconnect.com", "WalletConnect (Reown)"),
    ("reown.com", "WalletConnect (Reown)"),
    ("web3modal.org", "WalletConnect (Reown)"),
    ("sentry.io", "Sentry"),
    ("launchdarkly.com", "LaunchDarkly"),
    ("cloudflare.com", "Cloudflare"),
    ("country.is", "country.is"),
    ("githubusercontent.com", "GitHub"),
    ("sequence.info", "Sequence"),
    ("dm8wquhbuh2eq.cloudfront.net", "Sequence"),
    ("publicnode.com", "Custom RPC (user-set)"),
]


def operator(host: str) -> str:
    for suffix, name in OPERATORS:
        if host == suffix or host.endswith("." + suffix):
            return name
    return host


# --- service categories ----------------------------------------------------------------------
# (category, tier floor, default technique key)
CATS = {
    "App code & assets": "static",
    "Config & metadata": "static",
    "Account state": "backend_read",
    "Targeted messaging": "backend_read",
    "Security screening (Zodiac)": "backend_read",
    "Tx preview & simulation": "intent",
    "Tx security scan": "intent",
    "Tx proposal & signatures": "intent",
    "RPC: chain status": "rpc_public",
    "RPC: gas & fees": "rpc_public",
    "RPC: account & contract reads": "rpc_read",
    "RPC: tx tracking": "rpc_read",
    "RPC: name resolution (ENS)": "rpc_name",
    "RPC: sanctions screening": "rpc_sanctions",
    "RPC: broadcast": "intent",
    "Swap: order history": "backend_read",
    "Swap: balance watcher": "backend_read",
    "Swap: prices & token search": "rpc_public",
    "Swap: quote": "intent",
    "Swap: order submit & tracking": "intent",
    "Swap: notifications": "backend_read",
    "Analytics": "telemetry",
    "Error reporting": "telemetry",
    "Feature flags": "telemetry",
    "Bot challenge": "challenge",
    "IP geolocation": "challenge",
}

SANCTIONS_ORACLE = "0x40c57923924b5c5c5455c48d93317139addac8fb"
ENS_RESOLVERS = {"0xeeeeeeee14d718c2b47d9923deab1335e144eeee", "0xce01f8eee7e479c928f8919abd53e553a36cef67",
                 "0xc0497e381f536be9ce14b0dd3817cbcae57d2f62", "0x231b0ee14048e9dccd1d247744d114a4eb5e8e63"}
RPC_PRIORITY = ["RPC: broadcast", "RPC: sanctions screening", "RPC: name resolution (ENS)",
                "RPC: account & contract reads", "RPC: tx tracking", "RPC: gas & fees", "RPC: chain status"]


def rpc_item_category(item: dict) -> str:
    m = item.get("method", "")
    p = item.get("params") or []
    if m in ("eth_sendRawTransaction", "eth_sendTransaction"):
        return "RPC: broadcast"
    if m == "eth_call" and p and isinstance(p[0], dict):
        to = (p[0].get("to") or "").lower()
        if to == SANCTIONS_ORACLE:
            return "RPC: sanctions screening"
        if to in ENS_RESOLVERS:
            return "RPC: name resolution (ENS)"
        return "RPC: account & contract reads"
    if m in ("eth_getBalance", "eth_getCode", "eth_getTransactionCount", "eth_getStorageAt", "eth_getLogs", "eth_estimateGas"):
        return "RPC: account & contract reads"
    if m in ("eth_getTransactionReceipt", "eth_getTransactionByHash"):
        return "RPC: tx tracking"
    if m in ("eth_gasPrice", "eth_maxPriorityFeePerGas", "eth_feeHistory", "eth_blobBaseFee"):
        return "RPC: gas & fees"
    return "RPC: chain status"


def rpc_items(rec: dict) -> list:
    try:
        body = json.loads(rec["req_body"].get("text") or "")
    except (ValueError, TypeError):
        return []
    return body if isinstance(body, list) else [body]


STATIC_RE = re.compile(r"\.(js|mjs|css|svg|png|webp|jpe?g|gif|woff2?|ttf|ico|webmanifest|mp4|html)$")


def category(rec: dict) -> str:
    host, url, method = rec["host"], rec["url"], rec["method"]
    path = urlparse(url).path
    op = operator(host)
    if op == "Google Analytics":
        return "Analytics" if "collect" in path else "App code & assets"
    if op == "Sentry":
        return "Error reporting"
    if op == "LaunchDarkly":
        return "Feature flags"
    if op == "Cloudflare":
        return "Bot challenge"
    if op == "country.is":
        return "IP geolocation"
    if op == "WalletConnect (Reown)":
        if host.startswith("pulse."):
            return "Analytics"
        return "App code & assets" if host.startswith("fonts.") else "Config & metadata"
    if op in ("GitHub", "Sequence"):
        return "Config & metadata" if path.endswith(".json") else "App code & assets"
    if host.startswith("rpc.") or host.endswith("batch.exchange") or op == "Custom RPC (user-set)":
        if method == "OPTIONS":
            return "RPC: chain status"
        cats = {rpc_item_category(i) for i in rpc_items(rec)}
        for c in RPC_PRIORITY:
            if c in cats:
                return c
        return "RPC: chain status"
    if host == "zodiac-check.safe.global":
        return "Security screening (Zodiac)"
    if host == "simulation.safe.global" or "/preview" in path:
        return "Tx preview & simulation"
    if "threat-analysis" in path:
        return "Tx security scan"
    if path.endswith("/propose") or "/confirmations" in path:
        return "Tx proposal & signatures"
    if "targeted-messaging" in path:
        return "Targeted messaging"
    if host in ("safe-client.safe.global", "api.safe.global"):
        if re.search(r"/(owners|safes|transactions|delegates|relay|messages|nonces)\b", path) or "multisig" in path:
            if path.startswith("/v2/chains") and path.count("/") <= 2:
                return "Config & metadata"
            return "Account state"
        return "Config & metadata"
    if op == "CoW Protocol":
        if STATIC_RE.search(path):
            return "App code & assets"
        if re.search(r"/account/0x[0-9a-fA-F]{40}/orders", path):
            return "Swap: order history"
        if host.startswith("balances-watcher"):
            return "Swap: balance watcher"
        if path.endswith("/quote"):
            return "Swap: quote"
        if re.search(r"/orders|/app_data", path):
            return "Swap: order submit & tracking"
        if "telegram" in path or "notification-list" in path:
            return "Swap: notifications"
        if host.startswith("bff.") or host.endswith("batch.exchange"):
            return "Swap: prices & token search"
        if host.startswith("cms.") or path.endswith(".json"):
            return "Config & metadata"
        return "App code & assets"
    if STATIC_RE.search(path) or rec.get("resp_ctype", "").startswith(("image/", "font/", "text/css")):
        return "App code & assets"
    return "App code & assets" if host.startswith(("app.", "swap.")) else "Config & metadata"


INTENT_CATS = {"Tx preview & simulation", "Tx security scan", "Tx proposal & signatures", "RPC: broadcast",
               "Swap: quote", "Swap: order submit & tracking"}
TELEMETRY_CATS = {"Analytics", "Error reporting", "Feature flags", "Bot challenge", "IP geolocation"}
TIER_NAMES = ["Address-free", "Telemetry & fingerprint", "Address-linked read", "Intent before chain"]


def header(rec, name, which="req_headers"):
    for k, v in rec[which]:
        if k.lower() == name:
            return v
    return None


def identifiers(rec: dict, known: dict) -> list:
    hay = (rec["url"] + "\n" + "\n".join(f"{k}:{v}" for k, v in rec["req_headers"]) + "\n" +
           (rec["req_body"].get("text") or "")).lower()
    found = []
    for label, values in known.items():
        for v in values:
            v = v.lower()
            bare = v[2:] if v.startswith("0x") else v
            if v in hay or (len(bare) >= 40 and bare in hay):
                found.append(label)
                break
    q = parse_qs(urlparse(rec["url"]).query)
    if "cid" in q and operator(rec["host"]) == "Google Analytics":
        found.append("Client ID")
    if '"client_id":"did:key' in hay:
        found.append("Client ID")
    if header(rec, "cookie"):
        found.append("Cookie")
    return sorted(set(found))


def tier(cat: str, ids: list) -> int:
    addr = any(i in ids for i in ("Safe address", "Owner address", "Counterparty"))
    if cat in INTENT_CATS or "Tx hash / order id" in ids or ("Counterparty" in ids and addr and cat != "Account state"):
        return 3
    if addr:
        return 2
    if cat in TELEMETRY_CATS or "Client ID" in ids:
        return 1
    return 0


def load_jsonl(p: Path) -> list:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def analyze(run: Path, baseline_hosts: set) -> dict:
    flows = [r for r in load_jsonl(run / "flows.jsonl") if r["kind"] == "http"]
    ws = [r for r in load_jsonl(run / "flows.jsonl") if r["kind"] == "ws"]
    markers = load_jsonl(run / "markers.jsonl")
    steps = load_jsonl(run / "steps.jsonl")
    signer = load_jsonl(run / "signer.jsonl")
    state = json.loads((run / "state.json").read_text()) if (run / "state.json").exists() else {}

    owners = state.get("owners", {})
    known = {
        "Safe address": [state.get("safe", "")] if state.get("safe") else [],
        "Owner address": [owners.get("A", ""), owners.get("B", "")],
        "Counterparty": [owners.get("R", "")],
    }
    # Tx hashes and order ids that the run produced: safeTxHash from proposals, tx hashes from the signer.
    txids = set()
    for r in flows:
        t = r["req_body"].get("text") or ""
        for m in re.finditer(r'"safeTxHash"\s*:\s*"(0x[0-9a-fA-F]{64})"', t):
            txids.add(m.group(1))
        if r["url"].endswith("/api/v1/orders") and r["method"] == "POST":
            uid = (r["resp_body"].get("text") or "").strip('"')
            if uid.startswith("0x"):
                txids.add(uid)
    known["Tx hash / order id"] = sorted(txids)
    known = {k: [v for v in vs if v] for k, vs in known.items()}

    # Step windows from markers: "<name>" ... "<name>:end"
    windows = []
    open_ = {}
    for m in markers:
        n = m["name"]
        if n.endswith(":end"):
            s = n[:-4]
            if s in open_:
                windows.append((s, open_.pop(s), m["t"]))
        elif n not in ("session_start", "journey_end"):
            open_[n] = m["t"]

    def step_of(t):
        for s, a, b in windows:
            if a <= t <= b:
                return s
        return "(between steps)"

    out, browser_noise = [], Counter()
    for r in flows:
        if r["host"] in baseline_hosts:
            browser_noise[r["host"]] += 1
            continue
        cat = category(r)
        ids = identifiers(r, known)
        items = rpc_items(r) if (r["host"].startswith("rpc.") or r["host"].endswith(("batch.exchange", "publicnode.com"))) else []
        t_end = r["t_end"] or r["t_start"]
        out.append({
            "t": r["t_start"],
            "step": step_of(r["t_start"]),
            "method": r["method"],
            "host": r["host"],
            "path": re.sub(r"0x[0-9a-fA-F]{40,}", "0x…", urlparse(r["url"]).path)[:120],
            "operator": operator(r["host"]),
            "category": cat,
            "rpc_methods": [i.get("method") for i in items],
            "ids": ids,
            "tier": tier(cat, ids),
            "status": r["status"],
            "ms": round((t_end - r["t_start"]) * 1000, 1),
            "ttfb_ms": round(((r["t_resp_start"] or t_end) - (r["t_req_end"] or r["t_start"])) * 1000, 1),
            "up": r["req_wire_bytes"],
            "down": r["resp_wire_bytes"],
            "preflight": r["method"] == "OPTIONS",
            "fid": r["id"],
        })

    return {
        "run": run.name,
        "plan": state.get("plan"),
        "cookies": state.get("cookies"),
        "safe": state.get("safe"),
        "steps": steps,
        "windows": [{"name": s, "t0": a, "t1": b} for s, a, b in windows],
        "t0": markers[0]["t"] if markers else None,
        "requests": out,
        "websocket_messages": len(ws),
        "browser_noise": dict(browser_noise),
        "signer_calls": Counter(s["method"] for s in signer),
        "known_ids": {k: len(v) for k, v in known.items()},
        "known_values": known,
    }


def main():
    args = sys.argv[1:]
    run = Path(args[0])
    base = set()
    if "--baseline" in args:
        b = Path(args[args.index("--baseline") + 1])
        base = {r["host"] for r in load_jsonl(b / "flows.jsonl") if r.get("kind") == "http"}
    res = analyze(run, base)
    (run / "analysis.json").write_text(json.dumps(res, indent=1, default=list))
    reqs = res["requests"]
    print(f"{run.name}: {len(reqs)} requests, browser noise excluded {sum(res['browser_noise'].values())}")
    for t in range(4):
        print(f"  tier {t} {TIER_NAMES[t]:<24} {sum(1 for r in reqs if r['tier'] == t)}")
    c = Counter((r["operator"], r["category"]) for r in reqs)
    for (o, cat), v in sorted(c.items(), key=lambda x: -x[1])[:40]:
        print(f"  {v:5} {o:<22} {cat}")


if __name__ == "__main__":
    main()
