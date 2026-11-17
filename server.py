#!/usr/bin/env python3
"""Mirai by MindTech - demo backend (stdlib only).
Serves the static SPA and proxies triage/chat calls to the xAI API.
The API key is read at request time from env XAI_API_KEY (fallback: KEY_PATH) and is never logged or sent to the browser."""
import json, os, threading, time, urllib.request, urllib.error
from collections import deque
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")
KEY_PATH = "/home/box/.secrets/xai_api_key"
API_URL = "https://api.x.ai/v1/chat/completions"
MODEL = "grok-4.20-0309-non-reasoning"
MAX_TOKENS = 600
PORT = int(os.environ.get("PORT") or os.environ.get("MIRAI_PORT") or "8765")
RATE_GLOBAL = 60          # max model calls per rolling hour (all users)
RATE_PER_IP = 25          # max model calls per rolling hour per client IP
DATA = json.load(open(os.path.join(BASE, "data.json")))
ALERTS = {a["id"]: a for a in DATA["alerts"]}

_lock = threading.Lock()
_calls = deque()            # timestamps
_calls_ip = {}              # ip -> deque
_total_calls = 0

def rate_check(ip):
    global _total_calls
    now = time.time()
    with _lock:
        while _calls and now - _calls[0] > 3600: _calls.popleft()
        dq = _calls_ip.setdefault(ip, deque())
        while dq and now - dq[0] > 3600: dq.popleft()
        if len(_calls) >= RATE_GLOBAL: return False, "Demo rate limit reached (60 AI calls/hour). Please try again later."
        if len(dq) >= RATE_PER_IP: return False, "Per-user demo limit reached. Please try again later."
        _calls.append(now); dq.append(now); _total_calls += 1
        return True, ""

def remaining():
    now = time.time()
    with _lock:
        return RATE_GLOBAL - sum(1 for t in _calls if now - t <= 3600)

SYSTEM = """You are the Mirai AI Security Engineer, part of "Mirai by MindTech", a white-label managed SIEM + SOC service from MindTech Services built on Wazuh (SIEM/XDR) and Kaseya (RMM / IT management).
You triage Wazuh alerts alongside human NOC and SOC analysts. You are human-governed: AI prepares the triage and recommendation, policy decides what is allowed, and a named analyst approves anything consequential. Every step is logged.
POLICY:
- You MAY auto-handle only low-risk, reversible actions: enrich with threat intel, open/annotate a ticket, add to watchlist, tag the alert, run read-only Kaseya inventory or patch-status queries, notify the asset owner, block a single external IP at the edge when the asset is a user endpoint and there is no business dependency.
- You MUST request human approval for anything disruptive or high-impact: isolating a host, disabling or resetting an account, revoking sessions, killing processes or quarantining files on servers, removing users from privileged groups, changing firewall rules on production, pushing emergency patches via Kaseya, or anything on Critical-criticality assets.
- Decision rule: choose needs_human_approval only if at least one recommended action is high risk / requires approval. If the alert is benign or low/medium risk and every action you recommend is low risk, choose auto_handle and perform those actions yourself (list them in auto_actions_taken). Do not escalate routine noise; analysts' time matters.
- If evidence is ambiguous or severity is Critical, recommend escalation to a SOC analyst.
Be precise and concise. Use real MITRE ATT&CK technique IDs. Never invent facts beyond the alert and asset context; state assumptions. All data in this demo is sample data."""

TRIAGE_INSTR = """Triage this Wazuh alert using the Kaseya asset context. Respond ONLY with a JSON object with exactly these keys:
{"severity": "Critical|High|Medium|Low|Informational",
 "confidence": <integer 0-100>,
 "verdict": "true_positive_likely|suspicious_needs_review|benign_likely",
 "summary": "<one sentence>",
 "mitre": {"technique_id": "T####(.###)", "technique_name": "...", "tactic": "..."},
 "reasoning": ["<short bullet>", "... 3-5 bullets"],
 "recommended_actions": [{"action": "<short>", "risk": "low|high", "requires_approval": true|false}],
 "decision": "auto_handle|needs_human_approval",
 "decision_rationale": "<one sentence citing policy>",
 "auto_actions_taken": ["<low-risk actions the AI performed automatically, may be empty>"],
 "proposed_action_for_approval": "<the single most important action needing human approval, or empty string if auto_handle>"}
Keep each string short. 3-5 recommended actions."""

def call_xai(messages, json_mode=False):
    key = os.environ.get("XAI_API_KEY", "").strip()
    if not key:
        try:
            with open(KEY_PATH) as f: key = f.read().strip()
        except OSError:
            key = ""
    if not key:
        raise RuntimeError("AI backend not configured")
    body = {"model": MODEL, "messages": messages, "max_tokens": MAX_TOKENS, "temperature": 0.2}
    if json_mode: body["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(API_URL, data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"AI provider error (HTTP {e.code})")
    except Exception:
        raise RuntimeError("AI provider unreachable")
    return out["choices"][0]["message"]["content"], out.get("usage", {})

def parse_json(text):
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`"); t = t[t.find("{"):]
    s, e = t.find("{"), t.rfind("}")
    return json.loads(t[s:e+1])

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw): super().__init__(*a, directory=STATIC, **kw)

    def log_message(self, fmt, *args):  # request line only; never headers/bodies
        print("%s - %s" % (self.client_ip(), fmt % args), flush=True)

    def client_ip(self):
        return (self.headers.get("CF-Connecting-IP") or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or self.client_address[0])

    def send_json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if self.path == "/api/data": return self.send_json(200, DATA)
        if self.path == "/api/status": return self.send_json(200, {"ok": True, "model": MODEL, "remaining_this_hour": remaining()})
        return super().do_GET()

    def do_POST(self):
        try:
            n = min(int(self.headers.get("Content-Length", 0)), 20000)
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self.send_json(400, {"error": "bad request"})
        if self.path == "/api/triage": return self.triage(req)
        if self.path == "/api/chat": return self.chat(req)
        return self.send_json(404, {"error": "not found"})

    def triage(self, req):
        alert = ALERTS.get(req.get("alert_id"))
        if not alert: return self.send_json(404, {"error": "unknown alert"})
        ok, msg = rate_check(self.client_ip())
        if not ok: return self.send_json(429, {"error": msg})
        asset = DATA["assets"].get(alert["agent"], {})
        user = TRIAGE_INSTR + "\n\nWAZUH ALERT (sample):\n" + json.dumps(alert, indent=1) + "\n\nKASEYA ASSET CONTEXT (sample):\n" + json.dumps(asset, indent=1)
        try:
            text, usage = call_xai([{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}], json_mode=True)
            result = parse_json(text)
        except RuntimeError as e:
            return self.send_json(502, {"error": str(e)})
        except Exception:
            return self.send_json(502, {"error": "AI returned an unparseable response"})
        print(f"triage {alert['id']} tokens={usage.get('total_tokens')}", flush=True)
        self.send_json(200, {"alert_id": alert["id"], "result": result, "remaining_this_hour": remaining()})

    def chat(self, req):
        msgs = req.get("messages", [])
        if not isinstance(msgs, list) or not msgs: return self.send_json(400, {"error": "no messages"})
        clean = []
        for m in msgs[-8:]:
            if isinstance(m, dict) and m.get("role") in ("user", "assistant") and isinstance(m.get("content"), str):
                clean.append({"role": m["role"], "content": m["content"][:2000]})
        if not clean or clean[-1]["role"] != "user": return self.send_json(400, {"error": "last message must be from user"})
        ok, msg = rate_check(self.client_ip())
        if not ok: return self.send_json(429, {"error": msg})
        ctx = ("Sample alert queue (full details, JSON) currently visible to the analyst:\n" + json.dumps(DATA["alerts"], separators=(",", ":"))
               + "\nKaseya asset context (sample):\n" + json.dumps(DATA["assets"], separators=(",", ":")))
        sys = SYSTEM + "\n\nFor free chat: answer in plain text (light markdown ok), under 180 words. Only state facts present in the alert data; check timestamps before claiming sequence. Never mention word counts.\n" + ctx
        try:
            text, usage = call_xai([{"role": "system", "content": sys}] + clean)
        except RuntimeError as e:
            return self.send_json(502, {"error": str(e)})
        print(f"chat tokens={usage.get('total_tokens')}", flush=True)
        self.send_json(200, {"reply": text, "remaining_this_hour": remaining()})

if __name__ == "__main__":
    print(f"Mirai demo on http://0.0.0.0:{PORT} model={MODEL}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
