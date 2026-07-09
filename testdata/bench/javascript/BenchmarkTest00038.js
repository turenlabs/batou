// Safe: XSS prevented via xss library
const express = require('express');
const xss = require('xss');
const router = express.Router();
router.get('/test038', (req, res) => {
    const input = req.query.input;
    const clean = xss(input);
    res.send('<div>' + clean + '</div>');
});
module.exports = router;
