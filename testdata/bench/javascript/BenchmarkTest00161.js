// Vulnerable: Open redirect via res.redirect with user URL
const express = require('express');
const router = express.Router();
router.get('/test161', (req, res) => {
    const url = req.query.url;
    res.redirect(url);
});
module.exports = router;
