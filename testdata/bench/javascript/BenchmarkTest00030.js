// Safe: XSS prevented via he.encode
const express = require('express');
const he = require('he');
const router = express.Router();
router.get('/test030', (req, res) => {
    const input = req.query.msg;
    const encoded = he.encode(input);
    res.send('<div>' + encoded + '</div>');
});
module.exports = router;
