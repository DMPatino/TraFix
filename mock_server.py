#!/usr/bin/env python3
"""
mock_server.py — Fake web server for sandboxed network traffic simulation.
Impersonates the top 20 US domains. Run this on your "server" host.
Listens on port 80 (HTTP). For HTTPS you can put nginx/stunnel in front.

Usage:
    sudo python3 mock_server.py [--port 80] [--host 0.0.0.0]

Requirements:
    pip install flask
"""

import argparse
import random
import time
from flask import Flask, request, Response, redirect

app = Flask(__name__)

# Top 20 US domains mapped to realistic-ish mock responses
DOMAIN_PROFILES = {
    "google.com":       {"title": "Google",          "body": "Search the world's information.", "color": "#fff"},
    "www.google.com":   {"title": "Google",          "body": "Search the world's information.", "color": "#fff"},
    "youtube.com":      {"title": "YouTube",         "body": "Watch, listen, and learn.", "color": "#0f0f0f"},
    "www.youtube.com":  {"title": "YouTube",         "body": "Watch, listen, and learn.", "color": "#0f0f0f"},
    "facebook.com":     {"title": "Facebook",        "body": "Connect with friends and the world.", "color": "#1877f2"},
    "www.facebook.com": {"title": "Facebook",        "body": "Connect with friends and the world.", "color": "#1877f2"},
    "amazon.com":       {"title": "Amazon",          "body": "Shop millions of items.", "color": "#131921"},
    "www.amazon.com":   {"title": "Amazon",          "body": "Shop millions of items.", "color": "#131921"},
    "wikipedia.org":    {"title": "Wikipedia",       "body": "The free encyclopedia.", "color": "#fff"},
    "www.wikipedia.org":{"title": "Wikipedia",       "body": "The free encyclopedia.", "color": "#fff"},
    "twitter.com":      {"title": "X / Twitter",     "body": "What's happening in the world.", "color": "#000"},
    "x.com":            {"title": "X",               "body": "What's happening in the world.", "color": "#000"},
    "reddit.com":       {"title": "Reddit",          "body": "The front page of the internet.", "color": "#ff4500"},
    "www.reddit.com":   {"title": "Reddit",          "body": "The front page of the internet.", "color": "#ff4500"},
    "instagram.com":    {"title": "Instagram",       "body": "Capture and share the world's moments.", "color": "#833ab4"},
    "www.instagram.com":{"title": "Instagram",       "body": "Capture and share the world's moments.", "color": "#833ab4"},
    "linkedin.com":     {"title": "LinkedIn",        "body": "The world's largest professional network.", "color": "#0a66c2"},
    "www.linkedin.com": {"title": "LinkedIn",        "body": "The world's largest professional network.", "color": "#0a66c2"},
    "netflix.com":      {"title": "Netflix",         "body": "Watch TV shows and movies anytime.", "color": "#141414"},
    "www.netflix.com":  {"title": "Netflix",         "body": "Watch TV shows and movies anytime.", "color": "#141414"},
    "bing.com":         {"title": "Bing",            "body": "Search — Microsoft Bing.", "color": "#fff"},
    "www.bing.com":     {"title": "Bing",            "body": "Search — Microsoft Bing.", "color": "#fff"},
    "microsoft.com":    {"title": "Microsoft",       "body": "Technology solutions for everyone.", "color": "#fff"},
    "www.microsoft.com":{"title": "Microsoft",       "body": "Technology solutions for everyone.", "color": "#fff"},
    "apple.com":        {"title": "Apple",           "body": "Think different.", "color": "#000"},
    "www.apple.com":    {"title": "Apple",           "body": "Think different.", "color": "#000"},
    "espn.com":         {"title": "ESPN",            "body": "The worldwide leader in sports.", "color": "#cc0000"},
    "www.espn.com":     {"title": "ESPN",            "body": "The worldwide leader in sports.", "color": "#cc0000"},
    "cnn.com":          {"title": "CNN",             "body": "Breaking news, latest news and videos.", "color": "#cc0000"},
    "www.cnn.com":      {"title": "CNN",             "body": "Breaking news, latest news and videos.", "color": "#cc0000"},
    "nytimes.com":      {"title": "The New York Times","body": "All the news that's fit to print.", "color": "#fff"},
    "www.nytimes.com":  {"title": "The New York Times","body": "All the news that's fit to print.", "color": "#fff"},
    "twitch.tv":        {"title": "Twitch",          "body": "Live streaming for gamers.", "color": "#9147ff"},
    "www.twitch.tv":    {"title": "Twitch",          "body": "Live streaming for gamers.", "color": "#9147ff"},
    "ebay.com":         {"title": "eBay",            "body": "Buy and sell electronics, cars, fashion.", "color": "#fff"},
    "www.ebay.com":     {"title": "eBay",            "body": "Buy and sell electronics, cars, fashion.", "color": "#fff"},
    "yahoo.com":        {"title": "Yahoo",           "body": "News, email, search and more.", "color": "#720e9e"},
    "www.yahoo.com":    {"title": "Yahoo",           "body": "News, email, search and more.", "color": "#720e9e"},
    "zoom.us":          {"title": "Zoom",            "body": "Video conferencing and web conferencing.", "color": "#2d8cff"},
    "www.zoom.us":      {"title": "Zoom",            "body": "Video conferencing and web conferencing.", "color": "#2d8cff"},
}

FAKE_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

def build_html(title, body, color):
    """Generate a plausible HTML page with realistic size (~20-60KB via padding)."""
    padding = "<!-- " + ("x" * random.randint(5000, 40000)) + " -->"
    text_color = "#fff" if color not in ("#fff", "#ffffff") else "#111"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>{title}</title>
  <style>
    body{{margin:0;background:{color};color:{text_color};font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}}
    .wrap{{text-align:center;padding:40px}}
    h1{{font-size:3rem;margin-bottom:12px}}
    p{{font-size:1.2rem;opacity:.7}}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{title}</h1>
    <p>{body}</p>
  </div>
  {padding}
</body>
</html>"""

def get_profile():
    host = request.headers.get("Host", "").split(":")[0].lower().strip()
    return DOMAIN_PROFILES.get(host, {
        "title": host or "Website",
        "body": "Welcome.",
        "color": "#fff"
    })

@app.route("/", defaults={"path": ""}, methods=["GET", "HEAD", "POST"])
@app.route("/<path:path>", methods=["GET", "HEAD", "POST"])
def catch_all(path):
    # Simulate realistic latency (5–120ms)
    time.sleep(random.uniform(0.005, 0.12))

    profile = get_profile()
    host = request.headers.get("Host", "unknown")

    if request.method == "HEAD":
        resp = Response("", status=200)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        resp.headers["Server"] = "nginx/1.24.0"
        resp.headers["X-Simulated-Host"] = host
        return resp

    html = build_html(profile["title"], profile["body"], profile["color"])
    resp = Response(html, status=200, mimetype="text/html")
    resp.headers["Server"] = "nginx/1.24.0"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "max-age=300"
    resp.headers["X-Simulated-Host"] = host
    app.logger.info(f"[{host}] {request.method} /{path} from {request.remote_addr}")
    return resp

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock domain server for sandboxed traffic simulation")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=80, help="Port to listen on (default: 80)")
    args = parser.parse_args()
    print(f"[*] Mock server starting on {args.host}:{args.port}")
    print(f"[*] Impersonating {len(set(v['title'] for v in DOMAIN_PROFILES.values()))} domains")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
