// Safe: SSRF prevented via URL allowlist
const express = require('express');
const router = express.Router();
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];
router.get('/test082', async (req, res) => {
    const url = req.query.url;
    const parsed = new URL(url);
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
        return res.status(403).json({ error: 'Host not allowed' });
    }
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});
module.exports = router;
