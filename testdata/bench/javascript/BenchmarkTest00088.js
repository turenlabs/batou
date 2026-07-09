// Safe: SSRF prevented via hardcoded base URL
const express = require('express');
const router = express.Router();
const API_BASE = 'https://api.example.com';
router.get('/test088', async (req, res) => {
    const path = req.query.path;
    const safePath = path.replace(/[^a-zA-Z0-9/._-]/g, '');
    const response = await fetch(API_BASE + '/' + safePath);
    const data = await response.json();
    res.json(data);
});
module.exports = router;
