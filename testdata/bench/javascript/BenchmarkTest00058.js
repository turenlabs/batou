// Safe: Command injection prevented via dedicated library
const express = require('express');
const dns = require('dns');
const router = express.Router();
router.get('/test058', (req, res) => {
    const hostname = req.query.hostname;
    dns.lookup(hostname, (err, address) => {
        if (err) return res.status(400).json({ error: 'DNS lookup failed' });
        res.json({ address });
    });
});
module.exports = router;
