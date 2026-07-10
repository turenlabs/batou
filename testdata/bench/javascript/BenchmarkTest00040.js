// Safe: XSS prevented via strict content type (JSON)
const express = require('express');
const router = express.Router();
router.get('/test040', (req, res) => {
    const input = req.query.input;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ value: input }));
});
module.exports = router;
