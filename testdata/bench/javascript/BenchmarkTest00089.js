// Vulnerable: SSRF via variable indirection with fetch
const express = require('express');
const router = express.Router();
router.get('/test089', async (req, res) => {
    const input = req.query.service;
    const serviceUrl = input;
    const endpoint = serviceUrl + '/health';
    const response = await fetch(endpoint);
    const data = await response.json();
    res.json(data);
});
module.exports = router;
