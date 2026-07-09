// Vulnerable: SSRF via fetch with user-controlled URL
const express = require('express');
const router = express.Router();
router.get('/test081', async (req, res) => {
    const url = req.query.url;
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});
module.exports = router;
