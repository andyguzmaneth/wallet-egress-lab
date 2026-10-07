import json, sys
run, since = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else None)
marks = [json.loads(l) for l in open(f"{run}/markers.jsonl")]
t0 = next((m["t"] for m in marks if m["name"] == since), 0) if since else 0
for l in open(f"{run}/flows.jsonl"):
    r = json.loads(l)
    t = r.get("t_start") or r.get("t")
    if t < t0 or (r.get("host") or "").endswith("app.safe.global") and "/_next/" in r.get("url", ""): continue
    if r["kind"] == "ws":
        print(f"{t-t0:7.1f} WS{'>' if r['from_client'] else '<'} {r['host']} {r['len']}B {r.get('text','')[:150]}")
    else:
        b = r["req_body"].get("text", "")[:160]
        print(f"{t-t0:7.1f} {r['method']:4} {r['status']} {r['url'][:150]} {b}")
