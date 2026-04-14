"""GovScan Web Interface with API key auth + rate limiting."""
import os, time, threading
from datetime import datetime, UTC
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, abort

app = Flask(__name__)
API_KEYS = set(k.strip() for k in os.environ.get("GOVSCAN_API_KEYS","").split(",") if k.strip())
RATE_LIMIT = int(os.environ.get("GOVSCAN_RATE_LIMIT","5"))
rate_store, rate_lock = {}, threading.Lock()

def require_key(f):
    @wraps(f)
    def dec(*a,**kw):
        key = request.args.get("key") or request.headers.get("X-API-Key","")
        if API_KEYS and key not in API_KEYS:
            abort(401, description="Invalid or missing API key.")
        with rate_lock:
            now=time.time(); w=rate_store.get(key,[]); w=[t for t in w if now-t<3600]
            if len(w)>=RATE_LIMIT: abort(429, description=f"Rate limit: {RATE_LIMIT}/hour.")
            w.append(now); rate_store[key]=w
        return f(*a,**kw)
    return dec

@app.route("/")
def index():
    return render_template_string("""<!DOCTYPE html><html><head><meta charset=UTF-8><title>GovScan v1.0</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#08090d;color:#e2e8f0;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh}
.c{max-width:480px;padding:48px;text-align:center}h1{font-size:2em;font-weight:800;color:#0dd9a3}
.s{color:#64748b;font-size:.95em;margin:8px 0 32px}.b{background:#111827;border:1px solid #1e293b;border-radius:12px;padding:20px;text-align:left;font-size:.85em;color:#94a3b8;line-height:1.6}
code{background:#1e293b;padding:2px 6px;border-radius:4px;color:#3b82f6}</style></head>
<body><div class=c><h1>GovScan v1.0</h1><p class=s>Government Website Security Audit</p>
<div class=b><strong>Auth required.</strong> Use <code>?key=KEY</code> or <code>X-API-Key</code> header.<br><br>
<code>GET /api/scan?url=X&key=K</code> Scan URL<br>
<code>GET /api/status?key=K</code> Rate limit<br>
<code>GET /api/methodology</code> Scoring (no auth)</div></div></body></html>""")

@app.route("/api/status")
@require_key
def status():
    key=request.args.get("key") or request.headers.get("X-API-Key","")
    used=len(rate_store.get(key,[]))
    return jsonify(status="ok",version="1.0",rate_limit=RATE_LIMIT,used=used,remaining=RATE_LIMIT-used)

@app.route("/api/scan")
@require_key
def scan_single():
    url=request.args.get("url","").strip()
    if not url: return jsonify(error="Missing ?url="),400
    from govscan.scanner import scan_site
    from dataclasses import asdict
    return jsonify(asdict(scan_site({"institution":"","acronym":"","category":"","branch":"","url":url,"ds":""})))

@app.route("/api/methodology")
def methodology():
    return jsonify(formula="Final=(SSL*0.45)+(Headers*0.55)",
        ssl={"valid":80,"invalid":30,"none":0,"https_enforced":"+20"},
        headers={"CSP":15,"HSTS":15,"X-Frame":10,"X-Content-Type":10,"Referrer":5,"Permissions":5,"XSS":3},
        grades={"A":"85-100","B":"70-84","C":"55-69","D":"40-54","E":"25-39","F":"0-24"})

@app.errorhandler(401)
def e401(e): return jsonify(error=str(e.description)),401
@app.errorhandler(429)
def e429(e): return jsonify(error=str(e.description)),429

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
