"""mitmproxy addon: write one JSON line per HTTP flow and per WebSocket message.

Usage: mitmdump -q -s capture/record.py --set out=runs/<id>/flows.jsonl
"""
import base64
import json
import time

from mitmproxy import ctx, http

BODY_LIMIT = 512 * 1024


def _body(raw: bytes | None, ctype: str) -> dict:
    if not raw:
        return {"len": 0}
    out = {"len": len(raw)}
    text_like = any(t in ctype for t in ("json", "text", "javascript", "xml", "form", "graphql")) or not ctype
    if text_like:
        try:
            out["text"] = raw[:BODY_LIMIT].decode("utf-8")
            out["truncated"] = len(raw) > BODY_LIMIT
            return out
        except UnicodeDecodeError:
            pass
    if len(raw) <= 4096 and "image" not in ctype and "font" not in ctype:
        out["b64"] = base64.b64encode(raw).decode()
    return out


class Recorder:
    def __init__(self):
        self.fh = None

    def load(self, loader):
        loader.add_option("out", str, "flows.jsonl", "output JSONL path")

    def running(self):
        self.fh = open(ctx.options.out, "a", buffering=1)

    def _write(self, rec: dict):
        self.fh.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def response(self, flow: http.HTTPFlow):
        self._flow(flow)

    def error(self, flow: http.HTTPFlow):
        self._flow(flow)

    def _flow(self, flow: http.HTTPFlow):
        req, resp = flow.request, flow.response
        rctype = req.headers.get("content-type", "")
        sctype = resp.headers.get("content-type", "") if resp else ""
        self._write({
            "kind": "http",
            "id": flow.id,
            "t_start": req.timestamp_start,
            "t_req_end": req.timestamp_end,
            "t_resp_start": resp.timestamp_start if resp else None,
            "t_end": resp.timestamp_end if resp else time.time(),
            "method": req.method,
            "url": req.pretty_url,
            "host": req.pretty_host,
            "http_version": req.http_version,
            "status": resp.status_code if resp else None,
            "error": flow.error.msg if flow.error else None,
            "req_headers": list(req.headers.items(multi=True)),
            "resp_headers": list(resp.headers.items(multi=True)) if resp else [],
            "req_body": _body(req.raw_content, rctype),
            "resp_body": _body(resp.content if resp else None, sctype),
            "req_wire_bytes": len(req.raw_content or b"") + sum(len(k) + len(v) + 4 for k, v in req.headers.items(multi=True)),
            "resp_wire_bytes": (len(resp.raw_content or b"") + sum(len(k) + len(v) + 4 for k, v in resp.headers.items(multi=True))) if resp else 0,
            "client_conn": flow.client_conn.id,
            "server_conn": flow.server_conn.id if flow.server_conn else None,
            "server_ip": (flow.server_conn.peername or [None])[0] if flow.server_conn else None,
            "sni": flow.server_conn.sni if flow.server_conn else None,
            "is_websocket": flow.websocket is not None,
        })

    def websocket_message(self, flow: http.HTTPFlow):
        m = flow.websocket.messages[-1]
        content = m.content
        rec = {"kind": "ws", "flow_id": flow.id, "url": flow.request.pretty_url, "host": flow.request.pretty_host,
               "t": m.timestamp, "from_client": m.from_client, "len": len(content)}
        try:
            rec["text"] = content[:BODY_LIMIT].decode("utf-8")
        except UnicodeDecodeError:
            rec["b64"] = base64.b64encode(content[:4096]).decode()
        self._write(rec)


addons = [Recorder()]
