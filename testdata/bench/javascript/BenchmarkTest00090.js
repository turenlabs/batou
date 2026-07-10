// Safe: SSRF prevented via URL constructor hostname validation
const express = require('express');
const router = express.Router();
router.get('/test090', async (req, res) => {
    const input = req.query.url;
    try {
        const parsed = new URL(input);
        if (parsed.hostname !== 'api.trusted.com') {
            return res.status(403).json({ error: 'Only api.trusted.com allowed' });
        }
        const response = await fetch(parsed.href);
        res.json(await response.json());
    } catch (e) {
        res.status(400).json({ error: 'Invalid URL' });
    }
});
module.exports = router;
