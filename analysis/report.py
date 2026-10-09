"""Render one self-contained HTML report from analysed runs.

Writes the brief (index.html) and the full report (full.html) from one template.
Usage: python3 -I analysis/report.py --sepolia <run> [--mainnet <run>] --out report.html
       python3 -I analysis/report.py --sepolia <run> [--mainnet <run>] --site docs   (adds the run to the site)
"""
import argparse
import html
import time
import re
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

TIER_NAMES = ["Address-free", "Telemetry & fingerprint", "Address-linked read", "Transaction details before signing"]
TIER_HELP = [
    "No address or client ID; the receiver still sees the IP address, the time and what was fetched.",
    "A client or device ID, without an address.",
    "The Safe address or an owner address, which the receiver links to the IP address.",
    "What the user is about to do (recipient, amount, calldata, signature) before it is on chain.",
]
CONTEXT_CATS = {"RPC: account & contract reads", "Swap: prices & token search", "RPC: tx tracking", "RPC: name resolution (ENS)"}
ID_SHORT = {"Safe address": "Safe", "Owner address": "Owner", "Counterparty": "Counterparty", "Tx hash / order id": "Tx id", "Client ID": "Client ID"}
ID_COLS = ["Safe address", "Owner address", "Counterparty", "Tx hash / order id", "Client ID"]
OPERATOR_ORDER = ["Safe", "CoW Protocol", "Google Analytics", "WalletConnect (Reown)", "Sentry", "LaunchDarkly",
                  "Cloudflare", "Custom RPC (user-set)"]

# Assumed added latency per sequential request, in seconds. Sources are in the Method section.
TOR = 1.5          # Arti/Tor p50 for an RPC call (pir-wallet-bench, kass-tor run, 2026-10-06)
TORJS_LO, TORJS_HI = 0.93, 3.19   # tor-js in the browser, p50 per call, range over 7 runs (bench-runs 2026-09-18/21)
TORJS_BOOT = "12 to 50 s"         # tor-js bootstrap, same runs
PIR_TOR = "3 to 4 s"              # PIR over a native Tor client, p50 (pir-wallet-bench kass-tor: balance 2.9 s, all 4.2 s)
PIR_BROWSER = "10 to 18 s"        # PIR-sized request over tor-js, p50 (bench-runs 2026-09-18/21)
GAP = 0.5                         # a request depends on another if it starts within GAP s of that one ending
PIR = 1.75         # PIR balance lookup p50 over clearnet (pir-wallet-bench clean1)

TECH = {
    "static": ("Plain path; self-host third-party assets", 0.0),
    "telemetry": ("Do not send without consent; strip addresses", 0.0),
    "challenge": ("Needs the IP by design; check server-side or use privacy-pass tokens", 0.0),
    "backend_read": ("Hide origin: anon-RPC transport (Tor) in front of the API", TOR),
    "rpc_read": ("anon-RPC for origin; PIR for balance, nonce, code", TOR),
    "rpc_public": ("Plain path, or the same anonymous path", 0.0),
    "rpc_name": ("User's RPC or anon-RPC; cache; PIR name index later", TOR),
    "rpc_sanctions": ("Check a local copy of the public list", 0.0),
    "intent": ("Hide origin only (anon-RPC transport); simulate locally where possible", TOR),
}
CAT_TECH = {
    "App code & assets": "static", "Config & metadata": "static", "Account state": "backend_read",
    "Targeted messaging": "backend_read", "Security screening (Zodiac)": "backend_read",
    "Tx preview & simulation": "intent", "Tx security scan": "intent", "Tx proposal & signatures": "intent",
    "RPC: chain status": "rpc_public", "RPC: gas & fees": "rpc_public", "RPC: account & contract reads": "rpc_read",
    "RPC: tx tracking": "rpc_read", "RPC: name resolution (ENS)": "rpc_name", "RPC: sanctions screening": "rpc_sanctions",
    "RPC: broadcast": "intent", "Swap: order history": "backend_read",
    "Swap: balance watcher": "backend_read", "Swap: prices & token search": "rpc_public", "Swap: quote": "intent",
    "Swap: order submit & tracking": "intent", "Swap: notifications": "backend_read", "Analytics": "telemetry",
    "Error reporting": "telemetry", "Feature flags": "telemetry", "Bot challenge": "challenge", "IP geolocation": "challenge",
}
STEP_LABELS = {
    "cold_load": "Open app (first visit)", "connect_wallet": "Connect signer", "create_safe": "Create Safe (2-of-2)",
    "idle_empty": "Idle, empty Safe (60 s)", "receive_eth": "Receive ETH", "receive_token": "Receive WETH",
    "view_assets": "View assets", "view_history": "View history", "send_propose_A": "Send: owner A proposes",
    "send_confirm_execute_B": "Send: owner B confirms + executes", "swap_quote": "Swap: get quote",
    "swap_place_A": "Swap: owner A places order", "swap_execute_B": "Swap: owner B executes",
    "idle_home": "Idle on home (3 min)", "custom_rpc_set": "Set custom RPC", "custom_rpc_send_review": "Send review, custom RPC",
    "custom_rpc_idle": "Idle, custom RPC (60 s)", "open_safe_home": "Open public Safe", "view_positions": "View DeFi positions",
    "view_apps": "Open Safe Apps", "(between steps)": "Between steps",
}
IDLE_STEPS = {"idle_empty", "idle_home", "custom_rpc_idle", "receive_eth", "receive_token"}


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def num(n) -> str:
    return f"{n:,}"


def pct(a, b) -> str:
    return f"{(100 * a / b):.0f}%" if b else "0%"


def p(vals, q):
    if not vals:
        return 0
    vals = sorted(vals)
    k = min(len(vals) - 1, max(0, round(q * (len(vals) - 1))))
    return vals[k]


def kb(n) -> str:
    return f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / 1048576:.1f} MB"


def chain(reqs, weight=lambda r: 1):
    """Heaviest chain of requests where each starts within GAP s of the previous one ending (a likely dependency)."""
    rs = sorted(reqs, key=lambda r: r["t"])
    best = []
    for i, r in enumerate(rs):
        b = weight(r)
        for j in range(i):
            gap = r["t"] - (rs[j]["t"] + rs[j]["ms"] / 1000)
            if 0 <= gap <= GAP:
                b = max(b, best[j] + weight(r))
        best.append(b)
    return max(best) if best else 0


def op_bucket(o):
    return o if o in OPERATOR_ORDER else "Other"


def svg_timeline(a) -> str:
    reqs = [r for r in a["requests"] if not r["preflight"]]
    t0 = a["t0"]
    tmax = max(r["t"] for r in reqs) - t0
    lanes = [o for o in OPERATOR_ORDER if any(op_bucket(r["operator"]) == o for r in reqs)] + ["Other"]
    W, left, lane_h, top = 1000, 150, 22, 58
    H = top + lane_h * len(lanes) + 80
    x = lambda t: left + (W - left - 10) * (t / tmax)
    out = [f'<svg viewBox="0 0 {W} {H}" class="timeline" data-left="{left}" data-tmax="{tmax:.2f}" data-h="{H}" role="img" aria-label="Every request over the journey, by operator and tier">']
    for i, w in enumerate(a["windows"]):
        x0, x1 = x(w["t0"] - t0), x(w["t1"] - t0)
        out.append(f'<rect x="{x0:.1f}" y="{top - 4}" width="{max(1, x1 - x0):.1f}" height="{lane_h * len(lanes) + 4}" class="band b{i % 2}" data-step="{i}" data-t0="{w["t0"] - t0:.2f}" data-t1="{w["t1"] - t0:.2f}"/>')
    # Step numbers on two staggered rows, so short steps keep a label.
    last = [-99.0, -99.0]
    for i, w in enumerate(a["windows"]):
        x0, x1 = x(w["t0"] - t0), x(w["t1"] - t0)
        cx = (x0 + x1) / 2
        tc = (w["t0"] + w["t1"]) / 2 - t0
        row = 0 if cx - last[0] >= 20 else 1
        last[row] = cx
        y = top - 34 + row * 16
        lbl = esc(f'{i + 1}. {STEP_LABELS.get(w["name"], w["name"])}')
        out.append(f'<line x1="{cx:.1f}" x2="{cx:.1f}" y1="{y + 3}" y2="{top - 4}" class="steptick" data-step="{i}" data-t="{tc:.2f}"/>')
        out.append(f'<circle cx="{cx:.1f}" cy="{y - 4}" r="7.5" class="stepdot" data-step="{i}" data-t="{tc:.2f}" data-tip="{lbl}"/>')
        out.append(f'<text x="{cx:.1f}" y="{y}" class="steplbl" text-anchor="middle" data-step="{i}" data-t="{tc:.2f}">{i + 1}</text>')
    labels = [f'<rect x="0" y="{top - 4}" width="{left - 2}" height="{lane_h * len(lanes) + 4}" class="lblbg"/>']
    for li, lane in enumerate(lanes):
        y = top + li * lane_h + lane_h / 2
        labels.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" class="lanelbl">{esc(lane)}</text>')
        out.append(f'<line x1="{left}" x2="{W - 10}" y1="{y:.1f}" y2="{y:.1f}" class="lane tlane"/>')
    for r in sorted(reqs, key=lambda r: r["tier"]):
        li = lanes.index(op_bucket(r["operator"]))
        y = top + li * lane_h + lane_h / 2
        tip = f'{STEP_LABELS.get(r["step"], r["step"])} · {r["host"]}{r["path"]} · {TIER_NAMES[r["tier"]]} · {r["ms"]:.0f} ms'
        out.append(f'<rect x="{x(r["t"] - t0):.1f}" y="{y - 7:.1f}" width="2" height="14" rx="1" class="t{r["tier"]} req" data-t="{r["t"] - t0:.2f}" data-tip="{esc(tip)}"/>')
    # Annotations: a few notes that carry the story, under the lanes.
    base = top + lane_h * len(lanes) + 2
    win = {w["name"]: w for w in a["windows"]}
    notes = []
    def at(step, text):
        if step in win:
            w = win[step]
            notes.append((x((w["t0"] + w["t1"]) / 2 - t0), text, (w["t0"] + w["t1"]) / 2 - t0))
    n_create = sum(1 for r in reqs if r["step"] == "create_safe")
    at("create_safe", f"Create Safe: {num(n_create)} requests")
    n_cow = sum(1 for r in reqs if r["step"] == "swap_quote" and r["operator"] == "CoW Protocol")
    at("swap_quote", f"Swap opens: {num(n_cow)} CoW requests")
    g = idle_gap(reqs, win.get("idle_home"))
    if g:
        at("idle_home", f"Idle: Safe address every {g:.0f} s")
    n_saferpc = sum(1 for r in reqs if r["step"].startswith("custom_rpc") and r["host"] == "rpc.safe.global")
    if n_saferpc:
        at("custom_rpc_set", f"Custom RPC set: Safe RPC still called {n_saferpc}×")
    right = [-999.0, -999.0, -999.0]   # right edge of the last note in each row
    for nx, text, nt in sorted(notes):
        wtxt = len(text) * 6.8
        anchor = "end" if nx + wtxt > W - 6 else "start"
        l, r_ = (nx - wtxt - 4, nx) if anchor == "end" else (nx, nx + wtxt + 4)
        row = next((i for i, e in enumerate(right) if l > e + 8), len(right) - 1)
        right[row] = r_
        ty = base + 18 + row * 16
        tx = nx + (-4 if anchor == "end" else 4)
        out.append(f'<line x1="{nx:.1f}" x2="{nx:.1f}" y1="{base - 6}" y2="{ty - 3}" class="annline" data-t="{nt:.2f}"/>')
        out.append(f'<circle cx="{nx:.1f}" cy="{base - 6}" r="2.5" class="anndot" data-t="{nt:.2f}"/>')
        out.append(f'<text x="{tx:.1f}" y="{ty}" class="ann" text-anchor="{anchor}" data-t="{nt:.2f}" data-dx="{tx - nx:.0f}">{esc(text)}</text>')
    for m in range(0, int(tmax / 60) + 1, 5 if tmax < 1800 else 10):
        out.append(f'<text x="{x(m * 60):.1f}" y="{H - 6}" class="axis" text-anchor="middle" data-t="{m * 60}">{m} min</text>')
    # Lane names last, in a group the page script keeps pinned to the left edge while scrolling.
    out.append('<g class="lanelbls">' + "".join(labels) + "</g>")
    out.append("</svg>")
    return "".join(out)


def svg_steps(a) -> str:
    reqs = [r for r in a["requests"] if not r["preflight"]]
    by = defaultdict(lambda: [0, 0, 0, 0])
    for r in reqs:
        by[r["step"]][r["tier"]] += 1
    order = [w["name"] for w in a["windows"]]
    mx = max(sum(by[s]) for s in order)
    W, left, bh, gap = 1000, 250, 16, 8
    H = len(order) * (bh + gap) + 10
    out = [f'<svg viewBox="0 0 {W} {H}" class="bars" role="img" aria-label="Requests per step, stacked by tier">']
    for i, s in enumerate(order):
        y = 4 + i * (bh + gap)
        out.append(f'<text x="{left - 10}" y="{y + bh - 4}" text-anchor="end" class="lanelbl">{i + 1}. {esc(STEP_LABELS.get(s, s))}</text>')
        xx = left
        for t in range(4):
            n = by[s][t]
            if not n:
                continue
            w = (W - left - 70) * n / mx
            out.append(f'<rect x="{xx:.1f}" y="{y}" width="{max(w - 2, 1):.1f}" height="{bh}" rx="3" class="t{t}" data-tip="{esc(STEP_LABELS.get(s, s))}: {n} {esc(TIER_NAMES[t].lower())}"/>')
            xx += w
        out.append(f'<text x="{xx + 6:.1f}" y="{y + bh - 4}" class="axis">{num(sum(by[s]))}</text>')
    out.append("</svg>")
    return "".join(out)


def secs(x) -> str:
    return str(int(x + 0.5))


def svg_latency(proj) -> str:
    """Added wait per action over Tor, measured; the tor-js estimate range only when no Tor run exists."""
    if not proj:
        return ""
    measured = any(p_["meas"] is not None for p_ in proj)
    W, left, rh = 1000, 250, 26
    H = len(proj) * rh + 34
    mx = max((p_["meas"] or 0) if measured else p_["hi"] for p_ in proj) or 1
    x = lambda v: left + (W - left - 200) * v / mx
    step = 1 if mx <= 10 else 5 if mx <= 40 else 10
    out = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Added wait per action with the address-linked requests on Tor">']
    for v in range(0, int(mx) + 1, step):
        out.append(f'<line x1="{x(v):.1f}" x2="{x(v):.1f}" y1="4" y2="{H - 22}" class="lane"/>'
                   f'<text x="{x(v):.1f}" y="{H - 6}" class="axis" text-anchor="middle">+{v} s</text>')
    for i, p_ in enumerate(proj):
        y = 16 + i * rh
        lbl = STEP_LABELS.get(p_["step"], p_["step"])
        out.append(f'<text x="{left - 12}" y="{y + 4}" text-anchor="end" class="lanelbl">{esc(lbl)}</text>')
        if not measured:
            a_, b_ = x(p_["lo"]), x(p_["hi"])
            out.append(f'<line x1="{a_:.1f}" x2="{b_:.1f}" y1="{y}" y2="{y}" class="range" data-tip="{esc(lbl)}: estimate +{p_["lo"]:.1f} to {p_["hi"]:.1f} s"/>'
                       f'<text x="{b_ + 10:.1f}" y="{y + 4}" class="axis">+{secs(p_["lo"])} to {secs(p_["hi"])} s</text>')
        elif p_["meas"] is None:
            out.append(f'<text x="{left:.1f}" y="{y + 4}" class="axis">not measured</text>')
        else:
            b_ = max(x(p_["meas"]), left + 4)
            out.append(f'<rect x="{left}" y="{y - 5}" width="{b_ - left:.1f}" height="10" rx="4" class="t3" data-tip="{esc(lbl)}: +{p_["meas"]:.1f} s over Tor, {p_["n"]} requests routed"/>'
                       f'<text x="{b_ + 10:.1f}" y="{y + 4}" class="axis">+{p_["meas"]:.1f} s</text>')
    out.append("</svg>")
    return "".join(out)


def svg_units(reqs) -> str:
    """One square per request, grouped by receiver, colored by tier."""
    groups = ["Safe backend API", "Safe RPC", "Safe web app", "Third parties", "Custom RPC"]
    rows, cell, sq, gap, top = 14, 6.2, 5.2, 16, 36
    out, x0, lbl_right = [], 0.0, 0.0
    body = []
    for g in groups:
        rs = sorted((r for r in reqs if bucket(r) == g), key=lambda r: -r["tier"])
        if not rs:
            continue
        cols = -(-len(rs) // rows)
        for i, r in enumerate(rs):
            c, rr = divmod(i, rows)
            body.append(f'<rect x="{x0 + c * cell:.1f}" y="{top + rr * cell:.1f}" width="{sq}" height="{sq}" rx="1" class="t{r["tier"]}"/>')
        linked = sum(1 for r in rs if r["tier"] >= 2)
        tip = f"{g}: {num(len(rs))} requests, {num(linked)} address-linked"
        key = {"Safe backend API": "backend", "Safe RPC": "rpc", "Safe web app": "web", "Third parties": "third", "Custom RPC": "custom"}[g]
        body.append(f'<rect x="{x0 - 2:.1f}" y="{top - 2}" width="{cols * cell + 3:.1f}" height="{rows * cell + 3:.1f}" rx="3" class="ugrp" data-b="{key}" data-tip="{esc(tip)}"/>')
        body.append(f'<text x="{x0:.1f}" y="12" class="ulbl">{esc(g)}</text><text x="{x0:.1f}" y="27" class="axis">{num(len(rs))}</text>')
        lbl_right = max(lbl_right, x0 + len(g) * 8.6 + 6)
        x0 += cols * cell + gap
    W = max(x0 - gap, lbl_right)
    out.append(f'<svg viewBox="-2 0 {W + 4:.0f} {top + rows * cell + 4:.0f}" class="units" role="img" aria-label="Every request as one square, grouped by receiver and colored by tier">')
    out += body
    out.append("</svg>")
    return "".join(out)


def legend() -> str:
    return '<div class="legend">' + "".join(
        f'<span><i class="sw t{t}"></i>{esc(n)}</span>' for t, n in enumerate(TIER_NAMES)) + "</div>"


def mixbar(mix):
    segs = "".join(f'<i class="t{t}" style="flex:{n}" title="{n} {esc(TIER_NAMES[t].lower())}"></i>' for t, n in enumerate(mix) if n)
    lbl = ", ".join(f"{n} {TIER_NAMES[t].split()[0].lower()}" for t, n in reversed(list(enumerate(mix))) if n)
    return f'<div class="mix">{segs}</div><div class="sub">{esc(lbl)}</div>'


def inventory(a):
    groups = defaultdict(list)
    for r in a["requests"]:
        groups[(r["operator"], r["category"])].append(r)
    rows = []
    for (o, c), rs in groups.items():
        real = [r for r in rs if not r["preflight"]]
        ids = Counter(i for r in rs for i in r["ids"])
        tech, delta = TECH[CAT_TECH.get(c, "static")]
        rows.append({
            "operator": o, "category": c, "n": len(real), "preflight": len(rs) - len(real),
            "tier": max(r["tier"] for r in rs), "mix": [sum(1 for r in real if r["tier"] == t) for t in range(4)], "ids": [i for i in ID_COLS if ids[i]],
            "p50": p([r["ms"] for r in real], .5), "p95": p([r["ms"] for r in real], .95),
            "up": sum(r["up"] for r in rs), "down": sum(r["down"] for r in rs),
            "tech": tech, "hosts": sorted({r["host"] for r in rs}),
            "methods": Counter(m for r in rs for m in r["rpc_methods"]).most_common(3),
        })
    rows.sort(key=lambda r: (-(r["mix"][2] + r["mix"][3]), -r["mix"][1], -r["n"]))
    return rows


def bucket(r) -> str:
    if r["host"] in ("safe-client.safe.global", "api.safe.global"):
        return "Safe backend API"
    if r["host"] == "rpc.safe.global":
        return "Safe RPC"
    if r["operator"] == "Safe":
        return "Safe web app"
    if r["operator"] == "Custom RPC (user-set)":
        return "Custom RPC"
    return "Third parties"


def shape(r) -> str:
    if r["rpc_methods"]:
        return ", ".join(f"{m} ×{n}" if n > 1 else m for m, n in Counter(r["rpc_methods"]).most_common(2))
    path = re.sub(r"0x[0-9a-fA-F]{64}", "{hash}", r["path"].split("?")[0])
    path = re.sub(r"0x[0-9a-fA-F]{40}", "{address}", path)
    path = re.sub(r"/\d+(?=/|$)", "/{n}", path)
    return (r["host"] if bucket(r) == "Third parties" else "") + (path[:70] + ("…" if len(path) > 70 else ""))


REDACT_HEADERS = {"cookie", "authorization", "x-api-key"}
SHOW_HEADERS = ["content-type", "origin", "referer", "cookie", "authorization", "x-api-key"]


def load_flows(run_dir) -> dict:
    flows = {}
    for line in (Path(run_dir) / "flows.jsonl").read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get("kind") == "http":
                flows[r["id"]] = r
    return flows


def example_html(rec, known) -> str:
    """Render one captured request with the identifying parts marked."""
    from urllib.parse import urlsplit, parse_qsl, unquote
    u = urlsplit(rec["url"])
    lines = [f'{rec["method"]} {u.scheme}://{u.netloc}{unquote(u.path)}']
    q = parse_qsl(u.query, keep_blank_values=True)
    if len(u.query) > 100:
        lines += [f"  {'?' if i == 0 else '&'}{k}={v}" for i, (k, v) in enumerate(q)]
    elif u.query:
        lines[0] += "?" + unquote(u.query)
    for k, v in rec["req_headers"]:
        if k.lower() in SHOW_HEADERS:
            lines.append(f"{k}: " + (f"[{len(v)} bytes, redacted]" if k.lower() in REDACT_HEADERS else v[:160]))
    body = rec["req_body"].get("text") or ""
    if body:
        try:
            body = json.dumps(json.loads(body), indent=1)
        except ValueError:
            body = "\n".join((ln.replace("&", "\n&") if "=" in ln and "{" not in ln else ln.replace(',"', ',\n"')) if len(ln) > 200 else ln
                             for ln in body.split("\n"))
        lines += ["", body]
    text = re.sub(r"0{24,}", "0…0", "\n".join(lines))   # calldata padding
    pats = []
    for label, vals in known.items():
        for v in vals:
            bare = v[2:] if v.lower().startswith("0x") else v
            pats.append((re.compile(r"(?:0x)?" + re.escape(bare), re.I), "m-tx" if label.startswith("Tx") else "m-addr", label))
    pats.append((re.compile(r'"walletAddress"'), "m-ctx", "Address tag"))
    pats.append((re.compile(r"(?<=cid=)[0-9.]+"), "m-id", "Client ID"))
    pats.append((re.compile(r"did:key:[A-Za-z0-9]+"), "m-id", "Client ID"))
    pats.append((re.compile(r"\[\d+ bytes, redacted\]"), "m-id", "Cookie or token"))
    pats.append((re.compile(r"gcs=G100|pscdl=denied"), "m-ctx", "Analytics consent denied"))
    spans = sorted((mt.start(), mt.end(), cls, label) for rx, cls, label in pats for mt in rx.finditer(text))
    keep = []
    for sp in spans:
        if not keep or sp[0] >= keep[-1][1]:
            keep.append(sp)
    # Long payloads: keep the request line and the marked lines, with one line of context.
    starts = [0] + [m_.end() for m_ in re.finditer("\n", text)]
    line_of = lambda pos: max(k for k, st in enumerate(starts) if st <= pos)
    if len(starts) > 22 and keep:
        sel = {0}
        for a0, b0, *_ in keep[:10]:
            for ln in range(line_of(a0), line_of(b0) + 1):
                if 0 <= ln < len(starts):
                    sel.add(ln)
        ranges = []
        for ln in sorted(sel):
            if ranges and ln == ranges[-1][1] + 1:
                ranges[-1][1] = ln
            else:
                ranges.append([ln, ln])
        end_of = lambda ln: (starts[ln + 1] - 1) if ln + 1 < len(starts) else len(text)
        wins = [(starts[a_], end_of(b_)) for a_, b_ in ranges]
    else:
        wins = [(0, min(len(text), 2400))]
    out = []
    for wi, (a1, b1) in enumerate(wins):
        if wi or a1:
            prev = wins[wi - 1][1] if wi else 0
            gap = text.count(chr(10), prev, a1) - 1 if wi else text.count(chr(10), 0, a1)
            out.append(f'\n<span class="fold">… {gap} line{"s" if gap != 1 else ""}</span>\n')
        pos = a1
        for a0, b0, cls, label in keep:
            if a0 < a1 or b0 > b1:
                continue
            out.append(esc(text[pos:a0]))
            out.append(f'<mark class="{cls}" title="{esc(label)}">{esc(text[a0:b0])}</mark>')
            pos = b0
        out.append(esc(text[pos:b1]))
    if wins[-1][1] < len(text):
        out.append(f'\n<span class="fold">… {text.count(chr(10), wins[-1][1])} more lines</span>')
    labels = sorted({label for *_, label in keep})
    legend = "".join(f'<span class="tag">{esc(l)}</span>' for l in labels)
    return (f'<div class="exhead"><span class="sub">Example request. The receiver also sees</span> <mark class="m-id">your IP address</mark>'
            f'{" <span class=sub>and</span> " + legend if legend else ""}</div><pre class="expre">{"".join(out)}</pre>')


def breakdown(sens, flows=None, known=None) -> str:
    ids = {"Safe backend API": "backend", "Safe RPC": "rpc", "Safe web app": "web", "Third parties": "third", "Custom RPC": "custom"}
    out = []
    for b, key in ids.items():
        rs = [r for r in sens if bucket(r) == b]
        rows = []
        for j, ((o, c), n) in enumerate(Counter((r["operator"], r["category"]) for r in rs).most_common(8)):
            mine = [r for r in rs if r["category"] == c and r["operator"] == o]
            ex = Counter(shape(r) for r in mine).most_common(1)[0][0]
            who = f"{esc(o)} · " if b == "Third parties" else ""
            pick = None
            if flows:
                cands = [r for r in mine if r.get("fid") in flows]
                cands.sort(key=lambda r: (-len(r["ids"]), not flows[r["fid"]]["req_body"].get("text"), r["t"]))
                pick = cands[0] if cands else None
            if pick:
                xid = f"ex-{key}-{j}"
                rows.append(f'<tr class="bdrow" tabindex="0" role="button" aria-expanded="false" aria-controls="{xid}"><td class=num>{n}</td>'
                            f'<td>{who}{esc(c)}<div><code>{esc(ex)}</code></div></td><td class="exhint">Example</td></tr>'
                            f'<tr class="exrow" id="{xid}" hidden><td></td><td colspan="2">{example_html(flows[pick["fid"]], known or {})}</td></tr>')
            else:
                rows.append(f"<tr><td class=num>{n}</td><td>{who}{esc(c)}<div><code>{esc(ex)}</code></div></td><td></td></tr>")
        out.append(f'<div class="bdp" id="bd-{key}" hidden><h4>{esc(b)}: {len(rs)} address-linked requests</h4>'
                   f'<table>{"".join(rows) or "<tr><td>None</td></tr>"}</table></div>')
    return "".join(out)


def matrix(a):
    ops = defaultdict(lambda: Counter())
    for r in a["requests"]:
        if r["preflight"]:
            continue
        o = op_bucket(r["operator"]) if r["operator"] != "Safe" else (
            "Safe backend" if r["host"] in ("safe-client.safe.global", "api.safe.global") else
            "Safe RPC (eRPC)" if r["host"] == "rpc.safe.global" else "Safe web app & other")
        ops[o]["_total"] += 1
        ops[o]["_intent"] += r["tier"] == 3
        for i in r["ids"]:
            ops[o][i] += 1
    order = ["Safe backend", "Safe RPC (eRPC)", "Safe web app & other"] + OPERATOR_ORDER[1:] + ["Other"]
    return [(o, ops[o]) for o in order if ops[o]["_total"]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sepolia", required=True)
    ap.add_argument("--mainnet")
    ap.add_argument("--out", help="write one report file")
    ap.add_argument("--site", help="site root (docs): writes runs/<run>/index.html and rebuilds the run index")
    ap.add_argument("--back", default="../../index.html")
    ap.add_argument("--tor", help="the same journey captured over Tor, for measured latency")
    ap.add_argument("--clear", help="a clearnet run from the same session as --tor, to compare against")
    args = ap.parse_args()
    a = json.loads((Path(args.sepolia) / "analysis.json").read_text())
    m = json.loads((Path(args.mainnet) / "analysis.json").read_text()) if args.mainnet else None

    reqs = [r for r in a["requests"] if not r["preflight"]]
    flows = load_flows(args.sepolia)
    dur_min = (max(r["t"] for r in reqs) - a["t0"]) / 60
    sens = [r for r in reqs if r["tier"] >= 2]
    to_backend = sum(1 for r in sens if r["host"] in ("safe-client.safe.global", "api.safe.global"))
    to_rpc = sum(1 for r in sens if r["host"] == "rpc.safe.global")
    to_safe_other = sum(1 for r in sens if r["operator"] == "Safe") - to_backend - to_rpc
    to_custom = sum(1 for r in sens if r["operator"] == "Custom RPC (user-set)")
    to_third = len(sens) - to_backend - to_rpc - to_safe_other - to_custom
    idle_win = next((w for w in a["windows"] if w["name"] == "idle_home"), None)

    acts, covered, removed = actions(reqs, sens, idle_win, flows, a.get("known_values") or {})
    routed = lambda r: r["tier"] >= 2 and not r["preflight"] and not removed(r)
    tor_a = json.loads((Path(args.tor) / "analysis.json").read_text()) if args.tor else None
    clear_a = json.loads((Path(args.clear) / "analysis.json").read_text()) if args.clear else a

    def crit(run, step):
        rs = [r for r in run["requests"] if r["step"] == step and routed(r)]
        return chain(rs, lambda r: r["ms"] / 1000)

    # Added wait per action: estimate from the dependency chain, and measured when a Tor run is given.
    proj = []
    for w in a["windows"]:
        s = w["name"]
        if s in IDLE_STEPS:
            continue
        rs = [r for r in reqs if r["step"] == s and routed(r)]
        if not rs:
            continue
        d = chain(rs)
        meas = None
        if tor_a and any(x["name"] == s for x in tor_a["windows"]) and all(t["ok"] for t in tor_a["steps"] if t["name"] == s):
            # Compare with the same-day clearnet run; fall back to the main run where that step failed.
            ref = clear_a if all(t["ok"] for t in clear_a["steps"] if t["name"] == s) else a
            meas = max(0.0, crit(tor_a, s) - crit(ref, s))
        proj.append({"step": s, "n": len(rs), "depth": d, "lo": d * TORJS_LO, "hi": d * TORJS_HI, "meas": meas})

    # With every request on Tor, including the app's own code: how much longer the scripted steps took.
    full_tor = ""
    if tor_a:
        dur = lambda run: {t["name"]: t["ms"] / 1000 for t in run["steps"] if t["ok"]}
        dt, dc, da = dur(tor_a), dur(clear_a), dur(a)
        ui = ["cold_load", "view_assets", "view_history", "send_propose_A", "swap_quote", "custom_rpc_set"]
        diffs = [dt[n] - dc.get(n, da.get(n, dt[n])) for n in ui if n in dt]
        if diffs:
            full_tor = (f"With every request on Tor, including the app's own code, opening the app, viewing assets and history, proposing a send and "
                        f"getting a swap quote took {secs(min(diffs))} to {secs(max(diffs))} s longer per step.")
    tc = Counter(r["tier"] for r in reqs)
    inv = inventory(a)
    mat = matrix(a)

    custom_note = ""
    cr = [r for r in reqs if r["step"].startswith("custom_rpc")]
    if cr:
        cr_custom = sum(1 for r in cr if r["operator"] == "Custom RPC (user-set)")
        cr_saferpc = sum(1 for r in cr if r["host"] == "rpc.safe.global")
        cr_backend = sum(1 for r in cr if r["host"] == "safe-client.safe.global" and r["tier"] >= 2)
        cr_saferpc_m = Counter(r["category"] for r in cr if r["host"] == "rpc.safe.global")
        custom_note = (f"After a custom Sepolia RPC was set, {cr_custom} requests went to the custom node, "
                       f"{cr_saferpc} still went to Safe's RPC ({', '.join(f'{k.replace("RPC: ", "")} {v}' for k, v in cr_saferpc_m.most_common(3))}), "
                       f"and {cr_backend} address-linked reads went to the Safe backend. The setting replaces the chain RPC only.")

    mainnet_body, mainlink = "<p>No mainnet pass in this run.</p>", ""
    if m:
        mreqs = [r for r in m["requests"] if not r["preflight"]]
        s_pairs = {(r["operator"], r["category"]) for r in reqs}
        new = Counter((r["operator"], r["category"]) for r in mreqs if (r["operator"], r["category"]) not in s_pairs)
        msens = [r for r in mreqs if r["tier"] >= 2]
        rows = "".join(f"<tr><td>{esc(o)}</td><td>{esc(c)}</td><td class=num>{n}</td></tr>" for (o, c), n in new.most_common(12))
        mainlink = f" A read-only mainnet pass found {num(len(msens))} of {num(len(mreqs))} requests address-linked."
        mainnet_body = (f"<p>A read-only pass on mainnet watched a public Safe (<code>{esc(m['safe'][:10])}…</code>): {num(len(mreqs))} requests, "
                        f"{num(len(msens))} of them address-linked. Hosts that appeared on mainnet and not on Sepolia:</p>"
                        f'<div class="scroll"><table class="mini"><thead><tr><th>Operator</th><th>Service</th><th class=num>Requests</th></tr></thead><tbody>{rows or "<tr><td colspan=3>None</td></tr>"}</tbody></table></div>')

    inv_rows = []
    for r in inv:
        meth = ", ".join(f"{k} ×{v}" for k, v in r["methods"]) if r["methods"] else ""
        inv_rows.append(
            f'<tr data-tier="{r["tier"]}"{" class=extra" if len(inv_rows) >= 14 else ""}><td>{esc(r["operator"])}</td>'
            f'<td>{esc(r["category"])}<div class="sub">{esc(", ".join(r["hosts"][:2]) + (f" +{len(r['hosts']) - 2}" if len(r["hosts"]) > 2 else ""))}{(" · " + esc(meth)) if meth else ""}</div></td>'
            f'<td class=num data-v="{r["n"]}">{num(r["n"])}{f"<div class=sub>+{r["preflight"]} preflight</div>" if r["preflight"] else ""}</td>'
            f'<td data-v="{r["tier"] * 100000 + r["mix"][r["tier"]]}">{mixbar(r["mix"])}</td>'
            f'<td>{"".join(f"<span class=tag>{esc(ID_SHORT[i])}</span>" for i in r["ids"]) or "<span class=sub>none</span>"}</td>'
            + (f'<td class=num data-v="{r["p50"]}">{r["p50"]:.0f}<div class=sub>p95 {r["p95"]:.0f}</div></td>' if r["p50"] else '<td class=num data-v="0"><span class=sub>stream</span></td>') +
            f'<td class=num data-v="{r["up"] + r["down"]}">{kb(r["up"])}<div class=sub>{kb(r["down"])} down</div></td>'
            f'<td class=tech>{esc(r["tech"])}</td></tr>')

    mat_rows = []
    for o, c in mat:
        vals = [c[i] for i in ID_COLS] + [c["_intent"]]
        top = max(vals)
        cells = "".join(
            f'<td class="num heat{" top" if v and v == top else ""}">{num(v) if v else "·"}</td>' for v in vals)
        mat_rows.append(f'<tr><th scope=row>{esc(o)}</th><td class=num>{num(c["_total"])}</td>{cells}</tr>')

    proj_rows = "".join(
        f'<tr><td>{esc(STEP_LABELS.get(x["step"], x["step"]))}</td><td class=num>{x["n"]}</td>'
        f'<td class=num>{"not measured" if x["meas"] is None else f"+{x["meas"]:.1f} s"}</td></tr>' for x in proj)

    fails = [s for s in a["steps"] if not s["ok"]]
    fail_note = (" Steps that did not complete: " + ", ".join(esc(STEP_LABELS.get(s["name"], s["name"])) for s in fails) + ".") if fails else ""

    gap = idle_gap(reqs, idle_win)
    lo = min((x["lo"] for x in proj), default=0)
    hi = max((x["hi"] for x in proj), default=0)
    ms = [x["meas"] for x in proj if x["meas"] is not None]
    groups = [("Ship now", "No added latency"),
              ("Opt-in privacy mode · anon-RPC: requests over Tor hide the IP address", f"+{TORJS_LO:.1f} to {TORJS_HI:.1f} s per call in the browser, {TORJS_BOOT} to start"),
              ("Opt-in privacy mode · PIR: the server answers without learning the query", f"{PIR} s per lookup; {PIR_TOR} over Tor; {PIR_BROWSER} over Tor in the browser")]
    fix_html = []
    for gi, (gname, gcost) in enumerate(groups):
        rows = [x for x in acts if x[0] == gi]
        if not rows:
            continue
        lis = "".join(
            f'<li><div class="leak">{leak}</div><div class="fix">{fix} <button type="button" class="readmore fmore" aria-expanded="false">more</button>'
            f'<span class="fdet why" hidden> {det}</span></div><div class="chips-row"><span class="tag">{esc(n)}</span>'
            f'<span class="tag{" free" if c == "No added latency" else ""}">{esc(c)}</span>'
            f'{f"<span class=\"tag owner\">{esc(o)} owns this</span>" if o else ""}</div></li>'
            for _, leak, fix, det, n, c, o in rows)
        fix_html.append(f'<h3>{esc(gname)} <span class="gcost">{esc(gcost)}</span></h3><ol class="acts">{lis}</ol>')
    free = sum(1 for x in acts if x[5] == "No added latency")
    cover = "all " + num(len(sens)) if covered == len(sens) else pct(covered, len(sens)) + " of the"
    vals = {
        "THESIS": (f'<li><b>{pct(len(sens), len(reqs))}</b> of requests ({num(len(sens))} of {num(len(reqs))}) link the Safe or its owners to the user\'s IP.</li>'
                   f'<li><b>{pct(to_backend + to_rpc + to_safe_other, len(sens))}</b> of those go to Safe\'s own services, {pct(to_third, len(sens))} to third parties and {pct(to_custom, len(sens))} to the user\'s RPC.</li>'
                   f'<li><b>{len(acts)} fixes</b> cover {"all " + num(len(sens)) if covered == len(sens) else pct(covered, len(sens))}: {free} can ship now, {len(acts) - free} need anon-RPC or PIR.</li>'),
        "PICT_T": f"Safe's backend alone receives {pct(to_backend, len(sens))} of the address-linked requests",
        "FIX_T": f"{len(acts)} changes cover {cover} address-linked requests; {free} add no latency",
        "LAT_T": (f"Routing the address-linked requests over Tor added {min(ms):.1f} to {max(ms):.1f} s per action" if ms
                  else f"anon-RPC in the browser adds an estimated {secs(lo)} to {secs(hi)} s per action"),
        "FULLTOR": full_tor,
        "SESSION_T": f"The app keeps sending the Safe address while idle, a burst every {gap:.0f} s" if gap else "The session, request by request",
        "FIXES": "".join(fix_html), "MAINBODY": mainnet_body,
        "RUN": esc(a["run"]), "DATE": time.strftime("%Y-%m-%d", time.gmtime(a["t0"])), "BACK": esc(args.back),
        "NSTEPS": str(len(a["windows"])), "DUR": f"{dur_min:.0f}", "LEGEND": legend(), "UNITS": svg_units(reqs),
        "BREAKDOWN": breakdown(sens, flows, a.get("known_values")), "LATSVG": svg_latency(proj), "PROJ": proj_rows,
        "TIMELINE": svg_timeline(a), "STEPS": svg_steps(a),
        "STEPKEY": "".join(f'<li data-step="{i}"><b>{i + 1}</b> {esc(STEP_LABELS.get(w["name"], w["name"]))}</li>' for i, w in enumerate(a["windows"])),
        "MATRIX": "".join(mat_rows), "INV": "".join(inv_rows),
        "TIERHELP": "".join(f'<li><span><i class="sw t{t}"></i><b>{esc(TIER_NAMES[t])}.</b> {esc(TIER_HELP[t])}</span><span class="n">{num(tc[t])} requests</span></li>' for t in range(4)),
        "TOR": f"{TOR}", "TORJS": f"{TORJS_LO:.1f} to {TORJS_HI:.1f} s", "TORJS_BOOT": TORJS_BOOT, "PIR": f"{PIR}", "PIR_TOR": PIR_TOR,
        "PIR_BROWSER": PIR_BROWSER, "GAP": f"{GAP}", "FAILS": fail_note, "MAINLINK": mainlink,
        "COOKIES": "necessary only" if a.get("cookies") == "necessary" else "accept all", "REPO": REPO, "CUSTOM": esc(custom_note),
    }

    def render(full: bool) -> str:
        page = TEMPLATE
        for k, v in (vals | {
            "H1": "Safe{Wallet} Egress Report" if full else "Safe{Wallet} Egress Brief",
            "OTHER": "index.html" if full else "full.html", "OTHERLBL": "Short brief" if full else "Full report",
        }).items():
            page = page.replace("{{" + k + "}}", v)
        if full:
            # The full report is the same page with the appendix and the number tables open.
            page = re.sub(r'(class="apx-body" id="[^"]+") hidden', r"\1", page)
            page = page.replace('class="apx-toggle" aria-expanded="false"', 'class="apx-toggle" aria-expanded="true"')
            page = page.replace('<div id="lat-table" hidden>', '<div id="lat-table">')
            page = page.replace('data-show="lat-table">Show the numbers', 'data-show="lat-table">Hide the numbers')
        return page

    out = Path(args.out) if args.out else Path(args.site) / "runs" / a["run"] / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(False))
    (out.parent / "full.html").write_text(render(True))
    if args.site:
        # brief.html was the brief's address for one day; keep it working.
        (out.parent / "brief.html").write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=index.html">'
                                               '<title>Moved</title><a href="index.html">Moved to the run page</a>')
    print("wrote", out, "and", out.parent / "full.html")
    if args.site:
        meta = {
            "run": a["run"], "date": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(a["t0"])), "wallet": "Safe{Wallet} web",
            "plan": "Sepolia journey" + (" + mainnet read-only pass" if m else ""), "minutes": round(dur_min),
            "requests": len(reqs), "linked": len(sens), "linked_pct": pct(len(sens), len(reqs)),
            "steps_ok": sum(1 for s in a["steps"] if s["ok"]), "steps": len(a["steps"]),
            "backend_pct": pct(to_backend, len(sens)), "rpc_pct": pct(to_rpc, len(sens)), "cookies": a.get("cookies"),
        }
        (out.parent / "meta.json").write_text(json.dumps(meta, indent=2))
        build_index(Path(args.site))


SAFE_BACKEND_CATS = {"Account state", "Targeted messaging", "Tx preview & simulation", "Tx security scan",
                     "Tx proposal & signatures", "Security screening (Zodiac)"}


def cow_network(r):
    return r["path"].split("/")[1] if r["path"].count("/") > 2 else ""


def actions(reqs, sens, idle_win, flows, known):
    """The fix list. Each row: group, leak, fix, detail, cost, owner, predicate over requests."""
    is_rpc = lambda r: r["category"].startswith("RPC:")
    hist = [r for r in sens if r["category"] == "Swap: order history"]
    active = Counter(cow_network(r) for r in hist if r["host"] == "api.cow.fi").most_common(1)
    active = active[0][0] if active else ""
    fanout = lambda r: r["category"] == "Swap: order history" and not (r["host"] == "api.cow.fi" and cow_network(r) == active)
    n_prod = len({cow_network(r) for r in hist if r["host"] == "api.cow.fi"})
    n_barn = len({cow_network(r) for r in hist if r["host"].startswith("barn.")})
    safe_addr = (known.get("Safe address") or [""])[0].lower()
    pages = [r for r in sens if r["operator"] == "Safe" and CAT_TECH.get(r["category"]) == "static"]
    in_url = sum(1 for r in pages if safe_addr and safe_addr[2:] in flows.get(r.get("fid"), {}).get("url", "").lower())
    ens = [r for r in sens if r["category"] == "RPC: name resolution (ENS)"]
    ens_main = sum(1 for r in ens if r["host"] == "rpc.safe.global" and r["path"].startswith("/1/"))
    per_call = f"+{TORJS_LO:.1f} to {TORJS_HI:.1f} s per call"
    rows = [
        (0, "Google Analytics receives the Safe and owner addresses, with analytics declined.",
         "Send nothing without consent; drop addresses from events and URLs.",
         "Consent mode was denied, so Google drops cookies but still receives <code>ep.safeAddress</code>, <code>up.walletAddress</code> and the page URL. "
         "The client ID changes on each page load; the address is what links the visits.",
         "No added latency", None, lambda r: r["operator"] == "Google Analytics"),
        (0, "Page loads send the Safe address to Safe's web host, in the URL or the Referer header.",
         "Keep the address out of URLs and set a strict Referrer-Policy.",
         f"{in_url} requests carry <code>?safe=</code> in the URL and {len(pages) - in_url} in the Referer header; the host and its CDN can log both.",
         "No added latency", None, lambda r: r["operator"] == "Safe" and CAT_TECH.get(r["category"]) == "static"),
        (0, "Sanctions checks send the Safe and owner addresses to Safe's mainnet RPC, even on Sepolia.",
         "Check against a local copy of the public list.",
         "The checks call the Chainalysis oracle with <code>isSanctioned</code>. The list is small and can be rebuilt from the oracle's events, "
         "so the check stays and the address stays on the device.",
         "No added latency", None, lambda r: r["category"] == "RPC: sanctions screening"),
        (0, "The CoW widget's error reports to Sentry tag the Safe address.", "Strip addresses before a report leaves the browser.",
         "The address travels in a <code>walletAddress</code> tag and in request URLs.",
         "No added latency", "CoW", lambda r: r["operator"] == "Sentry"),
        (0, f"The CoW widget asks about the Safe on {n_prod} chains in production and {n_barn} on staging.",
         "Query the active chain and the production API only.",
         "The same widget looks up the user's IP address and country at <code>api.country.is</code>; that check can run server-side.",
         "No added latency", "CoW", fanout),
        (0, "WalletConnect reports a persistent client ID although it is not used.", "Load the SDK only when the user picks WalletConnect.",
         "Requests to <code>pulse.walletconnect.org</code> carry a <code>did:key</code> client ID from the first page load.",
         "No added latency", "Reown", lambda r: r["operator"] == "WalletConnect (Reown)"),
        (1, "Safe's backend sees the IP address with the Safe address, including transaction details before signing.",
         "Send backend calls through the anon-RPC transport (Tor).",
         f"The idle app asks about the Safe every {idle_gap(reqs, idle_win):.0f} s. Tor hides the IP address; Safe still sees which Safe, which owner and the pending transaction. "
         "The app page has to load over Tor too, or timing links the two.",
         per_call, None, lambda r: r["operator"] == "Safe" and r["category"] in SAFE_BACKEND_CATS),
        (1, "CoW's API sees the IP address with the Safe address, quotes and orders.", "Send CoW API calls through the same anon-RPC transport.",
         "Quotes, order submission, order tracking, notifications and the balance watcher all name the Safe.",
         per_call, "CoW", lambda r: r["operator"] == "CoW Protocol" and not is_rpc(r) and not fanout(r)),
        (1, f"ENS reverse lookups send owner and recipient addresses to an RPC; {ens_main} of {len(ens)} go to Safe's mainnet RPC during this Sepolia session.",
         "Resolve names over anon-RPC and cache the results.",
         "Names change rarely; a PIR name index can replace the lookup later.",
         per_call, None, lambda r: r["category"] == "RPC: name resolution (ENS)"),
        (2, "Every balance refresh tells Safe's backend which Safe the user holds.", "Read balances and tokens with PIR instead.",
         "A PIR lookup returns the balance without the server learning which account was asked about.",
         f"+{PIR_BROWSER} per lookup", None, lambda r: r["operator"] == "Safe" and r["category"] == "Account state" and "/balances" in r["path"]),
        (2, "RPC reads of balance, nonce, code and transaction status name the address, on Safe's RPC, CoW's nodes and a custom RPC alike.",
         "anon-RPC for the origin; PIR for ETH balance, nonce and listed tokens.",
         "Contract calls, simulation and gas estimates stay on anon-RPC.",
         f"{per_call}; +{PIR_BROWSER} per PIR lookup", None, lambda r: is_rpc(r) and r["category"] not in ("RPC: name resolution (ENS)", "RPC: sanctions screening")),
    ]
    out, covered = [], set()
    removed = [pred for g, *_, pred in rows if g == 0]
    for g, leak, fix, det, cost, owner, pred in rows:
        mine = [r for r in sens if pred(r)]
        if not mine:
            continue
        dup = sum(1 for r in mine if id(r) in covered)
        covered |= {id(r) for r in mine}
        tag = f"{num(len(mine))} address-linked" + (f", {num(dup)} also above" if dup else "")
        out.append((g, leak, fix, det, tag, cost, owner))
    return out, len(covered), (lambda r: any(p(r) for p in removed))


def idle_gap(reqs, idle_win) -> float:
    idle = sorted(r["t"] for r in reqs if r["step"] == "idle_home" and r["category"] == "Account state")
    starts = [t for i, t in enumerate(idle) if i == 0 or t - idle[i - 1] > 3]
    gaps = [b - a2 for a2, b in zip(starts, starts[1:])]
    return statistics.median(gaps) if idle_win and gaps else 0


REPO = "https://github.com/andyguzmaneth/wallet-egress-lab"
REPRO_CMDS = """git clone https://github.com/andyguzmaneth/wallet-egress-lab && cd wallet-egress-lab
npm install && npx playwright install chromium && uv tool install mitmproxy
scripts/run.sh sepolia     # setup, keys and the full command list are in the README"""


def repro_html(heading: str) -> str:
    return f"""<section id="reproduce">
  <div class="eyebrow">Reproduce</div>
  <h2>{heading}</h2>
  <p>Setup, method and techniques are in the <a href="{REPO}">repository README</a>. Testing another wallet means replacing the steps in <code>driver/journey.ts</code>.</p>
  <div class="codebox"><button type="button" class="copy" data-copy>Copy</button><pre><code>{esc(REPRO_CMDS)}</code></pre></div>
</section>"""


INDEX_TEMPLATE = (Path(__file__).parent / "index.html").read_text()
TEMPLATE = (Path(__file__).parent / "template.html").read_text()


def build_index(site: Path):
    metas = sorted((json.loads(f.read_text()) for f in site.glob("runs/*/meta.json")), key=lambda m: m["run"], reverse=True)
    rows = "".join(
        f'<tr><td><a href="runs/{esc(x["run"])}/index.html">{esc(x["date"])}</a><div class=sub>{esc(x["run"])} · <a href="runs/{esc(x["run"])}/full.html">full report</a></div></td>'
        f'<td>{esc(x["wallet"])}<div class=sub>{esc(x["plan"])}</div></td><td class=num>{x["minutes"]} min</td>'
        f'<td class=num>{num(x["requests"])}</td><td class=num>{num(x["linked"])}<div class=sub>{esc(x["linked_pct"])}</div></td>'
        f'<td class=num>{esc(x["backend_pct"])}</td><td class=num>{esc(x["rpc_pct"])}</td>'
        f'<td class=num>{x["steps_ok"]}/{x["steps"]}</td></tr>' for x in metas)
    latest = f'runs/{esc(metas[0]["run"])}/index.html' if metas else "#"
    (site / "index.html").write_text(INDEX_TEMPLATE.replace("{{ROWS}}", rows).replace("{{LATEST}}", latest).replace("{{N}}", f"{len(metas)} run{'' if len(metas) == 1 else 's'}").replace("{{REPRO}}", repro_html("Run it yourself")))
    (site / ".nojekyll").write_text("")
    print("wrote", site / "index.html")

if __name__ == "__main__":
    main()
