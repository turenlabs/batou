// Vulnerable: Open redirect via variable indirection
const express = require('express');
const router = express.Router();
router.get('/test167', (req, res) => {
    const target = req.query.target;
    const destination = target;
    res.redirect(destination);
});
module.exports = router;
