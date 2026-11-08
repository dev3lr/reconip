#!/usr/bin/env python3
"""
Web version of ipcheck. Standard library only.

    python server.py            -> http://localhost:8000

Environment variables:
    PORT                 port to listen on (hosting platforms set this)
    ABUSEIPDB_API_KEY    optional, enables abuse report history
    ANTHROPIC_API_KEY    optional, enables the Claude-written assessment
    AI_DAILY_LIMIT       max Claude-written reports per day (default 200), caps API spend
    TRUST_PROXY=N        number of reverse proxies in front of the app (Render/Railway/Fly/nginx: 1).
                         The visitor IP is read from the Nth-from-last X-Forwarded-For entry,
                         which visitors cannot forge. Leave unset when not behind a proxy.
    RATE_LIMIT           API calls per visitor per minute (default 45; one page lookup = 3)
"""

import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import insights
import ipcheck

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "static" / "index.html"
PORT = int(os.environ.get("PORT", "8000"))
TRUST_PROXY = int(os.environ.get("TRUST_PROXY") or 0)
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "45"))  # one page lookup = 3 API calls
CACHE_TTL = 15 * 60

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$")

_cache = {}            # ip -> (time, result)
_hood_cache = {}       # /24 -> (time, result)
_report_cache = {}     # ip -> (time, result)
HOOD_TTL = 60 * 60
_hits = {}             # client -> [timestamps]
_lock = threading.Lock()


def cached_lookup(ip):
    now = time.time()
    with _lock:
        hit = _cache.get(ip)
        if hit and now - hit[0] < CACHE_TTL:
            return hit[1]
    sources = ipcheck.check(ip)
    result = {"ip": ip, "verdict": ipcheck.analyze(ip, sources), "sources": sources,
              "checked_at": int(now)}
    with _lock:
        _cache[ip] = (now, result)
        if len(_cache) > 5000:  # keep memory bounded
            for k, _ in sorted(_cache.items(), key=lambda kv: kv[1][0])[:1000]:
                _cache.pop(k, None)
    return result


def _cached(store, key, ttl, fn):
    now = time.time()
    with _lock:
        hit = store.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    val = fn()
    with _lock:
        store[key] = (now, val)
        if len(store) > 2000:
            store.clear()
    return val


def cached_hood(ip):
    key = str(ipaddress.ip_network(f"{ip}/24", strict=False)) if ":" not in ip else ip
    return _cached(_hood_cache, key, HOOD_TTL, lambda: insights.neighborhood(ip))


def cached_report(ip):
    return _cached(_report_cache, ip, CACHE_TTL,
                   lambda: insights.report(ip, cached_lookup(ip), cached_hood(ip)))


def rate_ok(client):
    now = time.time()
    with _lock:
        recent = [t for t in _hits.get(client, []) if now - t < 60]
        if len(recent) >= RATE_LIMIT:
            _hits[client] = recent
            return False
        recent.append(now)
        _hits[client] = recent
        if len(_hits) > 10000:
            _hits.clear()
    return True


_server_ip = None
def server_public_ip():
    global _server_ip
    if _server_ip is None:
        _server_ip = ipcheck.http_json("http://ip-api.com/json/?fields=query").get("query")
    return _server_ip


class Handler(BaseHTTPRequestHandler):
    server_version = "recon-ip"
    sys_version = ""          # don't advertise the Python version
    timeout = 20              # drop stalled connections (slowloris)

    def client_ip(self):
        # Each proxy appends the address it received the request from, so only the last
        # TRUST_PROXY entries are trustworthy; anything to their left is visitor-controlled.
        if TRUST_PROXY:
            hops = [h.strip() for h in self.headers.get("X-Forwarded-For", "").split(",") if h.strip()]
            if len(hops) >= TRUST_PROXY:
                return hops[-TRUST_PROXY]
        return self.client_address[0]

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        super().end_headers()

    def send_json(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(url.query)

        if url.path in ("/", "/index.html"):
            body = INDEX.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if url.path == "/healthz":
            return self.send_json(200, {"ok": True})

        if url.path == "/api/me":
            ip = self.client_ip()
            try:
                if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
                    ip = server_public_ip()   # running locally: your public IP == server's
            except ValueError:
                pass
            return self.send_json(200, {"ip": ip})

        if url.path in ("/api/neighbors", "/api/report"):
            ip = (qs.get("ip") or [""])[0].strip()
            try:
                if not ipaddress.ip_address(ip).is_global:
                    raise ValueError
            except ValueError:
                return self.send_json(400, {"error": "Pass a public IP address as ?ip="})
            if not rate_ok(self.client_ip()):
                return self.send_json(429, {"error": f"Slow down: max {RATE_LIMIT} lookups per minute."})
            fn = cached_hood if url.path == "/api/neighbors" else cached_report
            return self.send_json(200, fn(ip))

        if url.path == "/api/lookup":
            q = (qs.get("q") or [""])[0].strip()
            if not q:
                return self.send_json(400, {"error": "Enter an IP address or hostname."})
            if not rate_ok(self.client_ip()):
                return self.send_json(429, {"error": f"Slow down: max {RATE_LIMIT} lookups per minute."})
            try:
                ip = str(ipaddress.ip_address(q))
            except ValueError:
                if not HOSTNAME_RE.match(q):
                    return self.send_json(400, {"error": "That doesn't look like an IP address or hostname."})
                try:
                    ip = socket.gethostbyname(q)
                except OSError:
                    return self.send_json(400, {"error": f"Couldn't resolve {q}."})
            addr = ipaddress.ip_address(ip)
            if not addr.is_global:
                return self.send_json(400, {"error": f"{ip} is a private or reserved address; there's nothing public to look up."})
            result = dict(cached_lookup(ip))
            result["query"] = q
            return self.send_json(200, result)

        self.send_json(404, {"error": "not found"})

    def log_request(self, code="-", size="-"):
        path = urllib.parse.urlparse(self.path).path      # drop ?q=/?ip=: searched IPs are not logged
        print(f"{self.log_date_time_string()} {self.client_ip()} {self.command} {path} {code}", flush=True)


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"recon-ip running on http://localhost:{PORT}", flush=True)
    srv.serve_forever()
