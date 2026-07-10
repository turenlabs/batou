// Vulnerable: SSRF via image proxy
const express = require('express');
const router = express.Router();
router.get('/test095', async (req, res) => {
    const imageUrl = req.query.src;
    const response = await fetch(imageUrl);
    const buffer = await response.arrayBuffer();
    res.set('Content-Type', response.headers.get('content-type'));
    res.send(Buffer.from(buffer));
});
module.exports = router;
