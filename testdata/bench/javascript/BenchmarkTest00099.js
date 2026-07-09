// Vulnerable: SSRF via request params building URL
const express = require('express');
const router = express.Router();
router.get('/test099', async (req, res) => {
    const host = req.query.host;
    const port = req.query.port;
    const path = req.query.path;
    const url = 'http://' + host + ':' + port + path;
    const response = await fetch(url);
    res.json(await response.json());
});
module.exports = router;
