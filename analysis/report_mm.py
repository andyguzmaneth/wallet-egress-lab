"""Render the MetaMask run as one local report page, comparable with the Safe report.

Usage: python3 -I analysis/report_mm.py --run runs/<mm-run> --baseline runs/<mm-baseline-run> \\
           [--safe runs/<safe-sepolia-run>] --out <file.html>

Reuses report.py's helpers and the page styling and script of template.html, so a Safe run renders
exactly as before. The headline counts only requests MetaMask itself sent (the extension, its service
worker and its snaps). The dapp page used for the swap is a separate party and gets its own section.
"""
import argparse
import json
import re
import time
from collections import Counter
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parent))   # python3 -I leaves the script's directory off the path
import report as R  # noqa: E402
from report import esc, num, pct  # noqa: E402

CONSENSYS = {"MetaMask (Consensys)", "Infura (Consensys)"}
NON_EVM = {"bitcoin-mainnet.infura.io", "solana-mainnet.infura.io", "tron-mainnet.infura.io", "stellar-mainnet.infura.io"}

R.OPERATOR_ORDER = ["MetaMask (Consensys)", "Infura (Consensys)", "Custom RPC (user-set)", "Hyperliquid", "Segment",
                    "Google (Firebase)", "Contentful"]
R.STEP_LABELS = R.STEP_LABELS | {
    "cold_load": "Install: onboarding tab opens", "connect_wallet": "Import phrase, decline usage data, open wallet",
    "select_sepolia": "Show test networks, pick Sepolia", "add_accounts": "Add account B and contact R",
    "idle_empty": "Idle, empty wallet (60 s)", "send_eth": "Send ETH: A to B", "swap_quote": "Swap: connect to CoW, get quote",
    "swap_place": "Swap: confirm in MetaMask", "custom_rpc_send_review": "Send review, custom RPC",
}
R.ID_COLS = ["Account address", "Non-EVM address", "Counterparty", "Tx hash / order id", "Client ID", "Profile ID"]
R.ID_SHORT = {"Account address": "Account", "Non-EVM address": "BTC/SOL/TRX/XLM", "Counterparty": "Counterparty",
              "Tx hash / order id": "Tx id", "Client ID": "Client ID", "Profile ID": "Profile", "Cookie": "Cookie"}
R.TIER_HELP = [
    "No address or client ID; the receiver still sees the IP address, the time and what was fetched.",
    "A client, device or profile ID, without an address.",
    "An account address (EVM or one of the derived Bitcoin, Solana, Tron and Stellar addresses), which the receiver links to the IP address.",
    "What the user is about to do (recipient, amount, calldata) before it is on chain: simulation, security scan, broadcast.",
]
R.CAT_TECH.update({"Account sync & sign-in": "backend_read", "Notifications": "backend_read", "Site screening": "backend_read",
                   "Prices, tokens & gas": "rpc_public", "Tx decoding": "rpc_public", "Non-EVM chain reads": "rpc_read"})

GROUPS = [("MetaMask API", "mmapi"), ("Infura: Ethereum networks", "evm"), ("Infura: Bitcoin, Solana, Tron, Stellar", "nonevm"),
          ("User's own RPC", "custom"), ("Third parties", "third")]

# Seen in the onboarding screens and the settings of 13.56.0 on 2026-11-09 (exploration session before the runs).
DEFAULTS = [
    ("Onboarding", "Gather basic usage data (MetaMetrics)", "On, pre-checked", "The run declined it."),
    ("Onboarding", "Marketing updates", "Off", ""),
    ("Security & privacy", "Basic functionality (master switch for token, NFT, price, ENS and phishing services)", "On", "13.56 has no separate per-service toggles."),
    ("Security & privacy", "IPFS gateway (dweb.link)", "On", ""),
    ("Backup and sync", "Backup and sync: accounts, contacts, buy and sell orders", "On", "A fresh import of a used phrase restored account B and contact R."),
    ("Notifications", "Allow notifications", "On", ""),
    ("Advanced", "Smart Transactions", "On", ""),
    ("Advanced", "Smart account requests from dapps", "On", "The swap upgraded account A to a smart account (EIP-7702)."),
    ("Networks", "Show test networks", "Off", "The run turned it on to reach Sepolia."),
    ("Networks", "Default RPC for the 8 preset networks", "Infura", ""),
    ("General", "Show default address, web widget on X", "On", ""),
]


def group(r) -> str:
    if r["operator"] == "Custom RPC (user-set)":
        return "User's own RPC"
    if r["host"] in NON_EVM:
        return "Infura: Bitcoin, Solana, Tron, Stellar"
    if r["operator"] == "Infura (Consensys)":
        return "Infura: Ethereum networks"
    if r["operator"] == "MetaMask (Consensys)":
        return "MetaMask API"
    return "Third parties"


def svg_units(reqs) -> str:
    rows, cell, sq, gap, top = 14, 6.2, 5.2, 16, 36
    x0, lbl_right, body = 0.0, 0.0, []
    for g, key in GROUPS:
        rs = sorted((r for r in reqs if group(r) == g), key=lambda r: -r["tier"])
        if not rs:
            continue
        cols = -(-len(rs) // rows)
        for i, r in enumerate(rs):
            c, rr = divmod(i, rows)
            body.append(f'<rect x="{x0 + c * cell:.1f}" y="{top + rr * cell:.1f}" width="{sq}" height="{sq}" rx="1" class="t{r["tier"]}"/>')
        linked = sum(1 for r in rs if r["tier"] >= 2)
        body.append(f'<rect x="{x0 - 2:.1f}" y="{top - 2}" width="{cols * cell + 3:.1f}" height="{rows * cell + 3:.1f}" rx="3" class="ugrp" data-b="{key}" '
                    f'data-tip="{esc(f"{g}: {num(len(rs))} requests, {num(linked)} address-linked")}"/>')
        body.append(f'<text x="{x0:.1f}" y="12" class="ulbl">{esc(g)}</text><text x="{x0:.1f}" y="27" class="axis">{num(len(rs))}</text>')
        lbl_right = max(lbl_right, x0 + len(g) * 7.6 + 6)
        x0 += max(cols * cell, len(g) * 7.6) + gap
    W = max(x0 - gap, lbl_right)
    return (f'<svg viewBox="-2 0 {W + 4:.0f} {top + rows * cell + 4:.0f}" class="units" role="img" '
            f'aria-label="Every MetaMask request as one square, grouped by receiver and colored by tier">' + "".join(body) + "</svg>")


def breakdown(sens, flows, known) -> str:
    out = []
    for g, key in GROUPS:
        rs = [r for r in sens if group(r) == g]
        rows = []
        for j, ((o, c), n) in enumerate(Counter((r["operator"], r["category"]) for r in rs).most_common(8)):
            mine = [r for r in rs if r["category"] == c and r["operator"] == o]
            ex = Counter(shape(r) for r in mine).most_common(1)[0][0]
            cands = sorted((r for r in mine if r["fid"] in flows), key=lambda r: (-len(r["ids"]), not flows[r["fid"]]["req_body"].get("text"), r["t"]))
            who = f"{esc(o)} · " if g == "Third parties" else ""
            xid = f"ex-{key}-{j}"
            rows.append(f'<tr class="bdrow" tabindex="0" role="button" aria-expanded="false" aria-controls="{xid}"><td class=num>{n}</td>'
                        f'<td>{who}{esc(c)}<div><code>{esc(ex)}</code></div></td><td class="exhint">Example</td></tr>'
                        f'<tr class="exrow" id="{xid}" hidden><td></td><td colspan="2">{R.example_html(flows[cands[0]["fid"]], known)}</td></tr>')
        out.append(f'<div class="bdp" id="bd-{key}" hidden><h4>{esc(g)}: {len(rs)} address-linked requests</h4>'
                   f'<table>{"".join(rows) or "<tr><td>None</td></tr>"}</table></div>')
    return "".join(out)


def shape(r) -> str:
    if r["rpc_methods"]:
        return ", ".join(f"{m} ×{n}" if n > 1 else m for m, n in Counter(r["rpc_methods"]).most_common(2))
    path = re.sub(r"0x[0-9a-fA-F]{64}|[0-9a-f]{64}", "{hash}", r["path"].split("?")[0])
    path = re.sub(r"0x…|\b(bc1|T)[0-9A-Za-z]{25,}|\bG[A-Z2-7]{55}\b", "{address}", path)
    return r["host"] + (path[:70] + ("…" if len(path) > 70 else ""))


def matrix(reqs):
    ops = {}
    for r in reqs:
        o = R.op_bucket(r["operator"])
        c = ops.setdefault(o, Counter())
        c["_total"] += 1
        c["_intent"] += r["tier"] == 3
        for i in r["ids"]:
            c[i] += 1
    return [(o, ops[o]) for o in R.OPERATOR_ORDER + ["Other"] if o in ops]


def mm_notes(reqs, win):
    out = []
    ob = [r for r in reqs if r["step"] == "connect_wallet"]
    ne = sum(1 for r in ob if r["host"] in NON_EVM and r["tier"] >= 2)
    if ne:
        out.append(("connect_wallet", f"Import: {num(ne)} Bitcoin/Solana/Tron/Stellar lookups"))
    sw = [r for r in reqs if r["step"] == "swap_place" and r["category"] == "Tx preview & simulation"]
    if sw:
        out.append(("swap_place", f"Confirm screen: {len(sw)} simulations"))
    idle = [r for r in reqs if r["step"] == "idle_home" and r["tier"] >= 2]
    if idle:
        out.append(("idle_home", f"Idle: {len(idle)} address-linked in 3 min"))
    return out


def alert_title(text: str) -> str:
    """'1 of 2 Unnecessary permission You're giving ...' -> 'Unnecessary permission' (the modal's heading)."""
    t = re.sub(r"^\d+ of \d+ ", "", text)
    return re.split(r" (?=You|To |We |This )", t, 1)[0]


def safe_compare(path):
    a = json.loads((Path(path) / "analysis.json").read_text())
    reqs = [r for r in a["requests"] if not r["preflight"]]
    sens = [r for r in reqs if r["tier"] >= 2]
    return {"run": a["run"], "n": len(reqs), "sens": len(sens), "own": sum(1 for r in sens if r["operator"] == "Safe"),
            "ga": sum(1 for r in sens if r["operator"] == "Google Analytics")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--baseline", required=True, help="the MetaMask extension-only baseline run")
    ap.add_argument("--safe", help="the Safe sepolia run, for the comparison table")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    a = json.loads((Path(args.run) / "analysis.json").read_text())
    base = json.loads((Path(args.baseline) / "analysis.json").read_text())
    state = json.loads((Path(args.run) / "state.json").read_text())
    flows = R.load_flows(args.run)
    known = a["known_values"]

    allr = [r for r in a["requests"] if not r["preflight"]]
    reqs = [r for r in allr if r["party"] == "wallet"]
    dapp = [r for r in allr if r["party"] == "dapp"]
    sens = [r for r in reqs if r["tier"] >= 2]
    wa = a | {"requests": [r for r in a["requests"] if r.get("party") == "wallet"]}   # MetaMask-only view for the charts
    dur_min = (max(r["t"] for r in allr) - a["t0"]) / 60
    cons = sum(1 for r in sens if r["operator"] in CONSENSYS)
    custom = sum(1 for r in sens if r["operator"] == "Custom RPC (user-set)")
    third = len(sens) - cons - custom
    nonevm = [r for r in sens if r["host"] in NON_EVM]
    imp = [r for r in reqs if r["step"] == "connect_wallet"]
    imp_sens = [r for r in imp if r["tier"] >= 2]
    cid = [r for r in reqs if "Client ID" in r["ids"]]
    prof = [r for r in reqs if "Profile ID" in r["ids"]]
    profile_put = [r for r in reqs if r["host"].startswith("authentication.") and "profile/accounts" in r["path"]]
    cr = [r for r in reqs if r["step"].startswith("custom_rpc")]
    cr_sens = Counter(group(r) for r in cr if r["tier"] >= 2)
    cr_infura_sep = sum(1 for r in cr if r["host"] == "sepolia.infura.io")
    cr_own = cr_sens.get("User's own RPC", 0)
    alerts = [n.split("acknowledged: ", 1)[1] for n in state.get("notes", []) if n.startswith("Confirmation alert")]
    tc = Counter(r["tier"] for r in reqs)

    thesis = (
        f'<li><b>{pct(len(sens), len(reqs))}</b> of the requests MetaMask sent ({num(len(sens))} of {num(len(reqs))}) link one of the user\'s addresses to the IP address.</li>'
        f'<li><b>{pct(cons, len(sens))}</b> of those go to Consensys (the MetaMask API and Infura), {pct(custom, len(sens))} to the RPC the user set, {pct(third, len(sens))} to third parties.</li>'
        f'<li><b>{num(len(nonevm))}</b> address-linked requests ask Infura about Bitcoin, Solana, Tron and Stellar mainnet accounts that MetaMask derived from the phrase. The user only used Sepolia.</li>'
        f'<li>Usage data declined: the MetaMetrics ID still went out in <b>{num(len(cid))}</b> requests, and backup and sync signed in to a MetaMask profile that lists every account of the phrase.</li>')

    gmax = max(Counter(group(r) for r in sens).items(), key=lambda x: x[1])
    vals = {
        "THESIS": thesis,
        "PICT_T": f"{gmax[0]} receives {pct(gmax[1], len(sens))} of MetaMask's address-linked requests",
        "UNITS": svg_units(reqs), "BREAKDOWN": breakdown(sens, flows, known),
        "LEGEND": R.legend(), "LEGEND_DESC": R.legend(desc=True),
        "TIMELINE": R.svg_timeline(wa, mm_notes), "STEPS": R.svg_steps(wa),
        "STEPKEY": "".join(f'<li data-step="{i}"><b>{i + 1}</b> {esc(R.STEP_LABELS.get(w["name"], w["name"]))}</li>' for i, w in enumerate(a["windows"])),
        "SESSION_T": f"Importing the phrase sends {num(len(imp_sens))} address-linked requests before the user opens a single screen",
    }

    # Findings, each with the count it rests on.
    nonevm_ops = Counter(r["host"].split("-")[0] for r in nonevm)
    findings = [
        ("Import queries every chain MetaMask supports.",
         f"The import step alone sent {num(len(imp))} requests, {num(len(imp_sens))} of them address-linked. "
         f"MetaMask derives Bitcoin, Solana, Tron and Stellar accounts from the phrase by default and asks Infura's mainnet endpoints about them "
         f"({', '.join(f'{k.title()} {v}' for k, v in nonevm_ops.most_common())} address-linked requests over the run). "
         "Bitcoin is queried by script hash for the first receive and change addresses of each account."),
        ("The profile service links all accounts of the phrase.",
         f"Backup and sync is on by default. It signs in with a key derived from the phrase, then registers each account with the authentication API "
         f"({len(profile_put)} PUT requests to /profile/accounts, one per account, each listing its EVM, Bitcoin, Solana, Tron and Stellar addresses with signed proofs, "
         f"under the same MetaMetrics ID, so accounts A and B sit in one profile). "
         f"{num(len(prof))} later requests carry the profile token. The rewards and notification APIs also receive the address lists."),
        ("Declining usage data stops Segment, not the MetaMetrics ID.",
         f"Segment received one event, \"Metrics Opt Out\", at the moment of the decline. The MetaMetrics ID then went to MetaMask's services in {num(len(cid))} requests."),
        ("A custom RPC moves Sepolia reads only.",
         f"After the custom Sepolia RPC was set, Sepolia reads went to it ({cr_own} address-linked) and "
         f"{cr_infura_sep} requests went to Infura Sepolia. In the same steps the MetaMask API still received {cr_sens.get('MetaMask API', 0)} and Infura's "
         f"non-EVM endpoints {cr_sens.get('Infura: Bitcoin, Solana, Tron, Stellar', 0)} address-linked requests."),
        ("A third party outside Consensys gets the address by default.",
         f"Hyperliquid's API received account A's address in {sum(1 for r in sens if r['operator'] == 'Hyperliquid')} requests (perpetuals balance lookups). The user never opened Perps."),
        ("The swap confirmation leaves before the user signs.",
         f"MetaMask's confirmation screen sent {sum(1 for r in reqs if r['category'] == 'Tx preview & simulation')} simulation requests and "
         f"{sum(1 for r in reqs if r['category'] == 'Tx security scan')} security scans with the transaction to MetaMask's servers. "
         + (f"It showed {len(alerts)} alerts, which the run acknowledged: " + "; ".join(esc(alert_title(x)) for x in alerts) + "." if alerts else "")),
    ]
    vals["FINDINGS"] = "".join(f"<li><b>{esc(h)}</b> {b}</li>" for h, b in findings)

    vals["DEFAULTS"] = "".join(f"<tr><td>{esc(w)}</td><td>{esc(s)}</td><td>{esc(d)}</td><td class=sub>{esc(n)}</td></tr>" for w, s, d, n in DEFAULTS)

    dsens = [r for r in dapp if r["tier"] >= 2]
    dops = Counter(r["operator"] for r in dapp)
    dtop = dops.most_common(8)
    dtop.append((f"{len(dops) - 8} other receivers", sum(dops.values()) - sum(n for _, n in dtop)))
    vals["DAPP"] = (f"<p>The swap ran on swap.cow.fi, because MetaMask Swaps lists no test networks. That page sent {num(len(dapp))} requests of its own, "
                    f"{num(len(dsens))} of them address-linked, to {len({r['host'] for r in dapp})} hosts, including its own Sepolia RPC at Alchemy and "
                    "advertising and analytics hosts. The page reads the address from MetaMask after the user connects; MetaMask does not send these requests. "
                    "They are left out of every MetaMask figure on this page.</p>"
                    '<div class="scroll"><table class="mini"><thead><tr><th>Receiver</th><th class=num>Requests</th></tr></thead><tbody>'
                    + "".join(f"<tr><td>{esc(o)}</td><td class=num>{num(n)}</td></tr>" for o, n in dtop) + "</tbody></table></div>")

    if args.safe:
        s = safe_compare(args.safe)
        vals["COMPARE"] = (
            '<div class="scroll"><table class="mini"><thead><tr><th></th><th class=num>Safe{Wallet} web</th><th class=num>MetaMask extension</th></tr></thead><tbody>'
            f'<tr><td>Requests the wallet sent</td><td class=num>{num(s["n"])}</td><td class=num>{num(len(reqs))}</td></tr>'
            f'<tr><td>Address-linked</td><td class=num>{num(s["sens"])} ({pct(s["sens"], s["n"])})</td><td class=num>{num(len(sens))} ({pct(len(sens), len(reqs))})</td></tr>'
            f'<tr><td>Of those, to the wallet vendor</td><td class=num>{pct(s["own"], s["sens"])} (Safe)</td><td class=num>{pct(cons, len(sens))} (Consensys)</td></tr>'
            f'<tr><td>Analytics after declining</td><td class=num>Google Analytics: {num(s["ga"])} address-linked</td><td class=num>Segment: 1 opt-out event; MetaMetrics ID in {num(len(cid))}</td></tr>'
            "</tbody></table></div>"
            f'<p class="sub">Unit: requests. Safe run {esc(s["run"])}. The journeys differ: Safe\'s count includes its web app, its swap widget and the multisig steps; '
            "MetaMask's excludes the swap page, which is a separate party, and has no multisig steps.</p>")
    else:
        vals["COMPARE"] = ""

    mat_rows = []
    for o, c in matrix(reqs):
        v = [c[i] for i in R.ID_COLS] + [c["_intent"]]
        top = max(v)
        mat_rows.append(f'<tr><th scope=row>{esc(o)}</th><td class=num>{num(c["_total"])}</td>'
                        + "".join(f'<td class="num heat{" top" if x and x == top else ""}">{num(x) if x else "·"}</td>' for x in v) + "</tr>")
    vals["MATRIX"] = "".join(mat_rows)
    inv_rows = []
    for r in R.inventory(wa):
        meth = ", ".join(f"{k} ×{v}" for k, v in r["methods"]) if r["methods"] else ""
        inv_rows.append(
            f'<tr data-tier="{r["tier"]}"{" class=extra" if len(inv_rows) >= 14 else ""}><td>{esc(r["operator"])}</td>'
            f'<td>{esc(r["category"])}<div class="sub">{esc(", ".join(r["hosts"][:2]) + (f" +{len(r["hosts"]) - 2}" if len(r["hosts"]) > 2 else ""))}{(" · " + esc(meth)) if meth else ""}</div></td>'
            f'<td class=num data-v="{r["n"]}">{num(r["n"])}</td><td data-v="{r["tier"] * 100000 + r["mix"][r["tier"]]}">{R.mixbar(r["mix"])}</td>'
            f'<td>{"".join(f"<span class=tag>{esc(R.ID_SHORT.get(i, i))}</span>" for i in r["ids"]) or "<span class=sub>none</span>"}</td>'
            + (f'<td class=num data-v="{r["p50"]}">{r["p50"]:.0f}</td>' if r["p50"] else '<td class=num data-v="0"><span class=sub>stream</span></td>')
            + f'<td class=num data-v="{r["up"] + r["down"]}">{R.kb(r["up"])}<div class=sub>{R.kb(r["down"])} down</div></td></tr>')
    vals["INV"] = "".join(inv_rows)

    bq = [r for r in base["requests"] if not r["preflight"]]
    fails = [s_ for s_ in a["steps"] if not s_["ok"]]
    vals |= {
        "TIERHELP": "".join(f'<li><span><i class="sw t{t}"></i><b>{esc(R.TIER_NAMES[t])}.</b> {esc(R.TIER_HELP[t])}</span><span class="n">{num(tc[t])} requests</span></li>' for t in range(4)),
        "BASELINE": (f"With the extension installed and never opened, for {round((base['requests'][-1]['t'] - base['t0']) / 60) if bq else 3} minutes, MetaMask sent "
                     f"{len(bq)} requests: " + ", ".join(sorted({f'{r["host"]}{r["path"]}' for r in bq})) + ". None carried an identifier."),
        "RUN": esc(a["run"]), "DATE": time.strftime("%Y-%m-%d", time.gmtime(a["t0"])), "VERSION": esc(state.get("version", "")),
        "NSTEPS": str(len(a["windows"])), "DUR": f"{dur_min:.0f}", "REPO": R.REPO,
        "FAILS": ("All " + str(len(a["steps"])) + " steps completed." if not fails else "Steps that failed: " + ", ".join(esc(s_["name"]) for s_ in fails) + "."),
        "NDAPP": num(len(dapp)), "NREQ": num(len(reqs)),
    }

    tpl = R.TEMPLATE
    head = tpl[:tpl.index("<body>")]
    script = tpl[tpl.index('<div class="tip" id="tip"></div>'):]
    body = (Path(__file__).parent / "template_mm.html").read_text()
    # noindex: the page may be shared by link; it should not be listed by search engines.
    page = head.replace("{{H1}}", "MetaMask Egress Report").replace("<head>", '<head>\n<meta name="robots" content="noindex">', 1) + body + script
    for k, v in vals.items():
        page = page.replace("{{" + k + "}}", v)
    left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", page)))
    if left:
        raise SystemExit(f"unfilled placeholders: {left}")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(page)
    print("wrote", args.out)


if __name__ == "__main__":
    main()
