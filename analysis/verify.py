"""Recount the brief's headline numbers from the raw capture, without analyze.py.

Usage: python3 -I analysis/verify.py runs/<sepolia-run> runs/<baseline-run>
Prints each figure next to the value the analysis produced, so a mismatch shows.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

run, base = Path(sys.argv[1]), Path(sys.argv[2])
load = lambda p: [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
flows = [r for r in load(run / "flows.jsonl") if r["kind"] == "http"]
noise = {r["host"] for r in load(base / "flows.jsonl") if r["kind"] == "http"}
state = json.loads((run / "state.json").read_text())
a = json.loads((run / "analysis.json").read_text())

reqs = [r for r in flows if r["host"] not in noise and r["method"] != "OPTIONS"]
addrs = [state["safe"], *state["owners"].values()]
txids = set()
for r in flows:
    txids |= set(re.findall(r'"safeTxHash"\s*:\s*"(0x[0-9a-fA-F]{64})"', r["req_body"].get("text") or ""))


def hay(r):
    return (r["url"] + "\n" + "\n".join(f"{k}:{v}" for k, v in r["req_headers"]) + "\n" + (r["req_body"].get("text") or "")).lower()


def linked(r):
    h = hay(r)
    return any(v.lower()[2:] in h for v in addrs + sorted(txids))


lk = [r for r in reqs if linked(r)]
backend = {"safe-client.safe.global", "api.safe.global"}
safe_own = [r for r in lk if r["host"].endswith("safe.global")]
rows = [
    ("requests (no preflight, no browser noise)", len(reqs), sum(1 for r in a["requests"] if not r["preflight"])),
    ("address-linked (raw substring search)", len(lk), sum(1 for r in a["requests"] if not r["preflight"] and r["tier"] >= 2)),
    ("  of which to Safe backend", sum(r["host"] in backend for r in lk), None),
    ("  of which to rpc.safe.global", sum(r["host"] == "rpc.safe.global" for r in lk), None),
    ("  of which to any *.safe.global", len(safe_own), None),
    ("Google Analytics, address-linked", sum("google-analytics" in r["host"] for r in lk), None),
    ("sanctions oracle calls (0x40c57923…)", sum("40c57923924b5c5c5455c48d93317139addac8fb" in hay(r) for r in reqs), None),
    ("ENS universal resolver calls (0xeeeeeeee14…)", sum("eeeeeeee14d718c2b47d9923deab1335e144eeee" in hay(r) for r in reqs), None),
    ("CoW order-history requests, address-linked", sum("/orders?" in r["url"] and "cow.fi" in r["host"] for r in lk), None),
    ("Sentry, address-linked", sum("sentry" in r["host"] for r in lk), None),
    ("WalletConnect pulse requests", sum("pulse.walletconnect" in r["host"] for r in reqs), None),
    ("backend /balances, address-linked", sum(r["host"] in backend and "/balances" in r["url"] for r in lk), None),
]
for name, mine, theirs in rows:
    flag = "" if theirs is None else ("  OK" if mine == theirs else f"  MISMATCH (analysis: {theirs})")
    print(f"{name:48s} {mine:6d}{flag}")
print(f"{'share address-linked':48s} {100 * len(lk) / len(reqs):5.1f}%")
print(f"{'share of linked on *.safe.global':48s} {100 * len(safe_own) / len(lk):5.1f}%")
only_a = {r['id'] for r in lk} ^ {r['fid'] for r in a['requests'] if not r['preflight'] and r['tier'] >= 2}
print("requests classified differently:", len(only_a))
for r in flows:
    if r["id"] in only_a:
        print("  ", r["method"], r["host"], r["url"][:90])
