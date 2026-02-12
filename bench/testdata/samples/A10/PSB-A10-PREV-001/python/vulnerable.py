# PSB-A10-PREV-001: URL preview/unfurl feature
# CWE: CWE-918
# Expected: GTSS-SSRF-001
from flask import Flask, request, jsonify
import requests
from bs4 import BeautifulSoup

app = Flask(__name__)

@app.route("/api/preview", methods=["POST"])
def preview():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "url is required"}), 400

    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        title = soup.title.string if soup.title else ""
        desc_tag = soup.find("meta", attrs={"name": "description"})
        description = desc_tag["content"] if desc_tag else ""
        img_tag = soup.find("meta", attrs={"property": "og:image"})
        image = img_tag["content"] if img_tag else ""

        return jsonify({"title": title, "description": description, "image": image})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run()
