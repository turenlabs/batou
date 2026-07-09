// Safe: Redirect prevented via fixed fallback
const express = require('express');
const router = express.Router();
router.get('/test176', (req, res) => {
    res.redirect('/dashboard');
});
module.exports = router;
