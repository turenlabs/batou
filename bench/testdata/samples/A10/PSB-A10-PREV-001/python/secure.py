# PSB-A10-PREV-001: URL preview/unfurl feature
# CWE: CWE-918
# Expected: (none - secure)
from flask import Flask, request, jsonify
import requests
import ipaddress
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

app = Flask(__name__)

BLOCKED_PORTS = {22, 25, 3306, 5432, 6379}

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    if parsed.port and parsed.port in BLOCKED_PORTS:
        return False
    try:
        addr = socket.getaddrinfo(hostname, None)[0][4][0]
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False
    except (socket.gaierror, ValueError):
        return False
    return True

@app.route("/api/preview", methods=["POST"])
def preview():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "url is required"}), 400
    if not is_safe_url(url):
        return jsonify({"error": "blocked URL"}), 400

    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        soup = BeautifulSoup(resp.text, "html.parser")

        title = soup.title.string if soup.title else ""
        desc_tag = soup.find("meta", attrs={"name": "description"})
        description = desc_tag["content"] if desc_tag else ""
        img_tag = soup.find("meta", attrs={"property": "og:image"})
        image = img_tag["content"] if img_tag else ""

        return jsonify({"title": title, "description": description, "image": image})
    except Exception:
        return jsonify({"error": "failed to fetch URL"}), 400

if __name__ == "__main__":
    app.run()
