// PSB-A10-PREV-001: URL preview/unfurl feature
// CWE: CWE-918
// Expected: GTSS-SSRF-001
const express = require("express");
const axios = require("axios");
const cheerio = require("cheerio");
const app = express();
app.use(express.json());

app.post("/api/preview", async (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ error: "url is required" });
  }

  try {
    const resp = await axios.get(url, { timeout: 10000 });
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
