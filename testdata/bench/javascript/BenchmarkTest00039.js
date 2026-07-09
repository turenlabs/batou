// Vulnerable: XSS via cookie value in HTML output
const express = require('express');
const router = express.Router();
router.get('/test039', (req, res) => {
    const theme = req.cookies.theme;
    res.send('<body class="' + theme + '">Content</body>');
});
module.exports = router;
