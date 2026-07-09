// Safe: SSRF prevented via URL scheme + domain regex
const express = require('express');
const router = express.Router();
router.post('/test092', async (req, res) => {
    const callbackUrl = req.body.callback;
    const urlPattern = /^https:\/\/[a-zA-Z0-9.-]+\.example\.com\//;
    if (!urlPattern.test(callbackUrl)) {
        return res.status(400).json({ error: 'Callback must be on example.com subdomain' });
    }
    const response = await fetch(callbackUrl, { method: 'POST', body: JSON.stringify({ ok: true }) });
    res.json({ status: 'sent' });
});
module.exports = router;
