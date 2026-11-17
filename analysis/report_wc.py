# WalletChan report: fill analysis/template_wc.html from <run>/analysis_wc.json.
# Usage: python3 -I analysis/report_wc.py <run> (--out <file.html> | --site docs) [--reviewed]
# --site writes docs/runs/<run>/index.html, full.html and meta.json and rebuilds the run index.
# Without --reviewed the page and its index row are marked as a draft the author has not reviewed.
import argparse, json, re, shutil, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import report as R
from report import esc, num, pct

VERSION = "4.2.0"

ap = argparse.ArgumentParser()
ap.add_argument("run")
ap.add_argument("--out"); ap.add_argument("--site"); ap.add_argument("--reviewed", action="store_true")
args = ap.parse_args()
a = json.load(open(Path(args.run) / "analysis_wc.json"))
rows = a["rows"]
marks = [json.loads(l) for l in open(Path(args.run) / "markers.jsonl")]
mt = {m["name"]: m["t"] for m in marks}
t0, t1 = marks[0]["t"], marks[-1]["t"]
linked = [x for x in rows if x["tier"] in ("address", "intent")]
idle = [x for x in rows if mt["idle_home"] <= x["t"] < mt["idle_home_end"]]
tiers = a["tiers"]

oprows = "".join(f"<tr><td>{esc(op)}</td><td class=num>{num(n)}</td><td class=num>{num(k)}</td></tr>" for op, n, k in a["operators"])
steprows = ""
for s, v in a["steps"].items():
    top = ", ".join(f"{esc(o)} {n}" for o, n in sorted(v["ops"].items(), key=lambda x: -x[1])[:3])
    more = len(v["ops"]) - 3
    steprows += (f"<tr><td>{esc(s.replace('_', ' '))}</td><td class=num>{v['n']}</td><td class=num>{v['addr']}</td>"
                 f"<td>{top}{f' <span class=sub>+{more} more</span>' if more > 0 else ''}</td></tr>")

vals = {
    "DATE": time.strftime("%Y-%m-%d", time.gmtime(t0)), "VERSION": VERSION, "DUR": f"{(t1 - t0) / 60:.0f}",
    "NWALLET": num(len(rows)), "NLINKED": num(len(linked)), "LINKEDPCT": pct(len(linked), len(rows)),
    "NOPS": str(len(a["ops_with_address"])), "IDLEN": str(len(idle)),
    "IDLEOPS": str(len({x["op"] for x in idle if x["tier"] != "free"})),
    "NPAGE": num(a["totals"]["page"]), "NBROWSER": num(a["totals"]["browser"]),
    "OPROWS": oprows, "STEPROWS": steprows,
    "T_FREE": num(tiers.get("free", 0)), "T_TEL": num(tiers.get("telemetry", 0)),
    "T_ADDR": num(tiers.get("address", 0)), "T_INTENT": num(tiers.get("intent", 0)),
    "RUN": esc(Path(args.run).name), "REPO": R.REPO,
    "BACKLINK": '<a class="back" href="../../index.html">All runs</a> · ' if args.site else "",
    "DRAFT": "" if args.reviewed else (
        '<div class="insight"><div class="eyebrow">Draft, not reviewed</div>'
        "<p>This page was generated with AI assistance from the run data and has not yet been reviewed by the author. "
        "Figures and wording may change.</p></div>"),
}
page = (Path(__file__).parent / "template_wc.html").read_text()
for k, v in vals.items():
    page = page.replace("{{" + k + "}}", v)
left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", page)))
if left:
    raise SystemExit(f"unfilled placeholders: {left}")
run = Path(args.run).name
out = Path(args.out) if args.out else Path(args.site) / "runs" / run / "index.html"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(page)
shutil.copy(out, out.parent / "full.html")   # the index links a full report for every run; this page has no appendix
print("wrote", out)
if args.site:
    own = sum(1 for x in linked if x["op"] in ("WalletChan", "eth.sh (WalletChan dev)"))
    default_rpc = sum(1 for x in linked if x["op"] not in ("WalletChan", "eth.sh (WalletChan dev)", "PublicNode (user-set RPC)"))
    meta = {
        "run": run, "date": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t0)),
        "wallet": f"WalletChan extension {VERSION}", "plan": "Sepolia journey",
        "minutes": round((t1 - t0) / 60), "requests": len(rows), "linked": len(linked), "linked_pct": pct(len(linked), len(rows)),
        "steps_ok": len(a["steps"]) - 1, "steps": len(a["steps"]) - 1,   # session_start is not a step
        # Index columns "To wallet backend" and "To default RPC": WalletChan's servers, and the shipped chain RPCs.
        "backend_pct": pct(own, len(linked)), "rpc_pct": pct(default_rpc, len(linked)),
        "status": "reviewed" if args.reviewed else "draft",
    }
    (out.parent / "meta.json").write_text(json.dumps(meta, indent=2))
    R.build_index(Path(args.site))
