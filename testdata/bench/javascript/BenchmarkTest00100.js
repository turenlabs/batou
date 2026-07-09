// Safe: SSRF prevented via fixed host and only path from user
const express = require('express');
const router = express.Router();
router.get('/test100', async (req, res) => {
    const apiPath = req.query.path;
    const safePath = apiPath.replace(/[^a-zA-Z0-9/_-]/g, '');
    const url = 'https://api.internal.example.com/' + safePath;
    const response = await fetch(url);
    res.json(await response.json());
});
module.exports = router;
