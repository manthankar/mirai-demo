# Mirai by MindTech · AI Security Engineer demo (prototype)

All alerts, hosts, and users are fictional sample data.

- `server.py` is a stdlib Python backend. It serves `static/` and proxies to xAI (`grok-4.20-0309-non-reasoning`, max_tokens 600).
  The key is read at request time from the `XAI_API_KEY` env var (fallback `/home/box/.secrets/xai_api_key`) and is never logged or sent to the browser.
  Rate limits: 60 AI calls/hour globally and 25/hour per IP. The counters live in memory and reset on restart.
- `data.json` holds the sample Wazuh alerts and the Kaseya asset context.
- `static/` holds `index.html`, `style.css`, `app.js` and the logo.
- API: `GET /api/data`, `GET /api/status`, `POST /api/triage {"alert_id"}`, `POST /api/chat {"messages"}`.

## Run / restart
    cd /workspace/mirai-demo
    pkill -f "python3 server.py"; setsid nohup python3 server.py > server.log 2>&1 < /dev/null &
    # open http://localhost:8765  (port from PORT or MIRAI_PORT; on Render, PORT is set automatically)

