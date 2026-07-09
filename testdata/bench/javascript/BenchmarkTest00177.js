// Vulnerable: Open redirect via template literal
const express = require('express');
const router = express.Router();
router.get('/test177', (req, res) => {
    const domain = req.query.domain;
    const path = req.query.path;
    res.redirect(`https://${domain}${path}`);
});
module.exports = router;
