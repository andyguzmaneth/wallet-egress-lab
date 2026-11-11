"""Recount a MetaMask run's headline numbers from the raw capture, without analyze.py.

Usage: python3 -I analysis/verify_mm.py runs/<mm-run> runs/<blank-baseline-run> [--spot N]
Prints each figure next to the value the analysis produced, so a mismatch shows, then N
address-linked and N address-free wallet requests with the raw field that decides it.
"""
import json
import random
import sys
from collections import Counter
from pathlib import Path

run, base = Path(sys.argv[1]), Path(sys.argv[2])
spot = int(sys.argv[sys.argv.index("--spot") + 1]) if "--spot" in sys.argv else 10
load = lambda p: [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
flows = [r for r in load(run / "flows.jsonl") if r["kind"] == "http"]
noise = {r["host"] for r in load(base / "flows.jsonl") if r["kind"] == "http"}
state = json.loads((run / "state.json").read_text())
derived = json.loads((run / "derived.json").read_text())
a = json.loads((run / "analysis.json").read_text())
fid = {r["fid"]: r for r in a["requests"]}

values = [state["accounts"][k] for k in ("A", "B", "R")] + list(derived.values())
values += [t["hash"] for t in state["txs"] if t["from"].lower() in {state["accounts"][k].lower() for k in ("A", "B", "R")}]
values = [v.lower()[2:] if v.startswith("0x") else v.lower() for v in values]
values = [v for v in values if v]


def hdr(r, name):
    return next((v for k, v in r["req_headers"] if k.lower() == name), "")


def hay(r):
    return (r["url"] + "\n" + "\n".join(f"{k}:{v}" for k, v in r["req_headers"]) + "\n" + (r["req_body"].get("text") or "")).lower()


def wallet(r):
    src = hdr(r, "origin") or hdr(r, "referer")
    return not (src.startswith("http") and "metamask.github.io" not in src)


reqs = [r for r in flows if r["host"] not in noise and r["method"] != "OPTIONS"]
w = [r for r in reqs if wallet(r)]
d = [r for r in reqs if not wallet(r)]
linked = lambda r: any(v in hay(r) for v in values)
# Transaction details before signing, without a known value: MetaMask's security scan and simulation
# endpoints, and broadcasts. Matched on the raw URL and body.
intent = lambda r: ("security-alerts.api.cx.metamask.io" in r["host"] or (r["host"].startswith("tx-sentinel") and r["method"] == "POST")
                    or "eth_sendrawtransaction" in hay(r))
sens = lambda r: linked(r) or (wallet(r) and intent(r))
wl, dl = [r for r in w if sens(r)], [r for r in d if linked(r)]
an = [r for r in a["requests"] if not r["preflight"]]
aw = [r for r in an if r["party"] == "wallet"]
ad = [r for r in an if r["party"] == "dapp"]
rows = [
    ("requests (no preflight, no browser noise)", len(reqs), len(an)),
    ("  sent by MetaMask (extension, worker, snaps)", len(w), len(aw)),
    ("  sent by the dapp page (CoW Swap)", len(d), len(ad)),
    ("MetaMask, address-linked or tx intent (raw search)", len(wl), sum(r["tier"] >= 2 for r in aw)),
    ("dapp, address-linked", len(dl), sum(r["tier"] >= 2 for r in ad)),
]
for name, mine, theirs in rows:
    flag = "  OK" if abs(mine - theirs) <= 1 else f"  MISMATCH (analysis: {theirs})"
    print(f"{name:52s} {mine:6d}{flag}")
print(f"{'share of MetaMask requests address-linked':52s} {100 * len(wl) / len(w):5.1f}%  (unit: requests)")
ops = Counter(fid[r["id"]]["operator"] for r in wl)
for o, n in ops.most_common():
    print(f"  {o:50s} {n:6d}  {100 * n / len(wl):5.1f}% of MetaMask's address-linked requests")
diff = {r["id"] for r in wl} ^ {r["fid"] for r in aw if r["tier"] >= 2}
print("MetaMask requests classified differently:", len(diff))
for r in flows:
    if r["id"] in diff:
        print("  ", r["method"], r["host"], r["url"][:90], fid.get(r["id"], {}).get("category"))

rnd = random.Random(7)
print(f"\nSpot check: {spot} address-linked MetaMask requests, the value found and where")
for r in rnd.sample(wl, min(spot, len(wl))):
    h = hay(r)
    v = next((v for v in values if v in h), None)
    if v is None:
        print(f"  {r['method']} {r['host']}{r['url'].split(r['host'])[-1][:50]}  [intent endpoint, no known value]")
        continue
    i = h.index(v)
    where = "url" if v in r["url"].lower() else "header" if v in "\n".join(f"{k}:{x}" for k, x in r["req_headers"]).lower() else "body"
    print(f"  {r['method']} {r['host']}{r['url'].split(r['host'])[-1][:50]}  [{where}] …{h[max(0, i - 30):i + len(v) + 10]}…")
print(f"\nSpot check: {spot} MetaMask requests the analysis calls address-free (tier 0 or 1): any known value in them?")
free = [r for r in w if fid[r["id"]]["tier"] < 2]
for r in rnd.sample(free, min(spot, len(free))):
    print(f"  {'CARRIES A VALUE' if linked(r) else 'clean':15s} {r['method']} {r['host']}{r['url'].split(r['host'])[-1][:60]}  body {len(r['req_body'].get('text') or '')} B")
