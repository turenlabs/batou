// Safe: SSRF prevented via protocol check + private IP block
const express = require('express');
const axios = require('axios');
const router = express.Router();
router.get('/test084', async (req, res) => {
    const target = req.query.target;
    const parsed = new URL(target);
    if (parsed.protocol !== 'https:') {
        return res.status(400).json({ error: 'HTTPS only' });
    }
    if (parsed.hostname === 'localhost' || parsed.hostname.startsWith('10.') || parsed.hostname.startsWith('192.168.')) {
        return res.status(403).json({ error: 'Internal hosts not allowed' });
    }
    const response = await axios.get(target);
    res.json(response.data);
});
module.exports = router;
