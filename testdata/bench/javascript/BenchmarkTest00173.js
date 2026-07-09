// Vulnerable: Open redirect in login callback
const express = require('express');
const router = express.Router();
router.get('/test173', (req, res) => {
    const callbackUrl = req.query.callback;
    res.redirect(callbackUrl);
});
module.exports = router;
