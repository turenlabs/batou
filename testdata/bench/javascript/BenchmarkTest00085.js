// Vulnerable: SSRF via http.get with user-controlled URL
const express = require('express');
const http = require('http');
const router = express.Router();
router.get('/test085', (req, res) => {
    const url = req.query.endpoint;
    http.get(url, (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => { res.send(data); });
    });
});
module.exports = router;
