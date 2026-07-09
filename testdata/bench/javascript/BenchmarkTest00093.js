// Vulnerable: SSRF via header value used as URL
const express = require('express');
const router = express.Router();
router.get('/test093', async (req, res) => {
    const proxyTarget = req.headers['x-proxy-url'];
    const response = await fetch(proxyTarget);
    const body = await response.text();
    res.send(body);
});
module.exports = router;
