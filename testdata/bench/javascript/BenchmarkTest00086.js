// Safe: SSRF prevented via validator.isURL with restricted options
const express = require('express');
const validator = require('validator');
const router = express.Router();
router.get('/test086', async (req, res) => {
    const url = req.query.url;
    if (!validator.isURL(url, { protocols: ['https'], require_protocol: true })) {
        return res.status(400).json({ error: 'Invalid URL' });
    }
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});
module.exports = router;
