// Safe: SSRF prevented via domain suffix check
const express = require('express');
const router = express.Router();
router.get('/test096', async (req, res) => {
    const imageUrl = req.query.src;
    try {
        const parsed = new URL(imageUrl);
        if (!parsed.hostname.endsWith('.cdn.example.com')) {
            return res.status(403).json({ error: 'Only CDN images allowed' });
        }
        const response = await fetch(imageUrl);
        const buffer = await response.arrayBuffer();
        res.set('Content-Type', response.headers.get('content-type'));
        res.send(Buffer.from(buffer));
    } catch (e) {
        res.status(400).json({ error: 'Invalid URL' });
    }
});
module.exports = router;
