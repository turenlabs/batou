// Vulnerable: XSS via variable indirection through res.send
const express = require('express');
const router = express.Router();
router.get('/test029', (req, res) => {
    const input = req.query.msg;
    const message = input;
    const output = '<div>' + message + '</div>';
    res.send(output);
});
module.exports = router;
