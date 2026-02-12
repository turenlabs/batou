// PSB-A10-PREV-001: URL preview/unfurl feature
// CWE: CWE-918
// Expected: (none - secure)
const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const dns = require("dns").promises;
const { URL } = require("url");
const net = require("net");
const app = express();
app.use(express.json());

async function isSafeUrl(urlStr) {
  const parsed = new URL(urlStr);
  if (!["http:", "https:"].includes(parsed.protocol)) return false;
  const addresses = await dns.resolve4(parsed.hostname);
  for (const addr of addresses) {
    if (net.isIP(addr) && (addr.startsWith("10.") || addr.startsWith("127.") ||
        addr.startsWith("169.254.") || addr.startsWith("192.168.") ||
        addr.startsWith("172.16.") || addr === "0.0.0.0")) {
      return false;
    }
  }
  return true;
}

app.post("/api/preview", async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "url is required" });
  }

  try {
    if (!(await isSafeUrl(url))) {
      return res.status(400).json({ error: "blocked URL" });
    }

    const resp = await axios.get(url, {
      timeout: 5000,
      maxRedirects: 0,
      maxContentLength: 1024 * 1024,
    });
    const $ = cheerio.load(resp.data);

    const title = $("title").text() || "";
    const description = $('meta[name="description"]').attr("content") || "";
    const image = $('meta[property="og:image"]').attr("content") || "";

    res.json({ title, description, image });
  } catch (err) {
    res.status(400).json({ error: "failed to fetch URL" });
  }
});

module.exports = app;
