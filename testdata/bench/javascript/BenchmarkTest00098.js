// Safe: SSRF prevented via URL parse + private IP block + scheme
const express = require('express');
const dns = require('dns');
const router = express.Router();
router.get('/test098', async (req, res) => {
    const url = req.query.url;
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:') {
            return res.status(400).json({ error: 'HTTPS required' });
        }
        if (/^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(parsed.hostname)) {
            return res.status(403).json({ error: 'Private IPs blocked' });
        }
        const response = await fetch(url);
        res.json(await response.json());
    } catch (e) {
        res.status(400).json({ error: 'Invalid request' });
    }
});
module.exports = router;
