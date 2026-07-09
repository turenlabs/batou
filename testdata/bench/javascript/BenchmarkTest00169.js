// Vulnerable: Open redirect via 301 with user input
const express = require('express');
const router = express.Router();
router.get('/test169', (req, res) => {
    const redirect = req.query.redirect;
    res.redirect(301, redirect);
});
module.exports = router;
