// Vulnerable: Open redirect via params
const express = require('express');
const router = express.Router();
router.get('/goto/:url', (req, res) => {
    const url = req.params.url;
    res.redirect(url);
});
module.exports = router;
