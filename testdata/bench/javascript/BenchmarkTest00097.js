// Vulnerable: SSRF via got HTTP client
const express = require('express');
const got = require('got');
const router = express.Router();
router.get('/test097', async (req, res) => {
    const url = req.query.feed;
    const response = await got(url);
    res.send(response.body);
});
module.exports = router;
