// Vulnerable: XSS via document.write in server-rendered script
const express = require('express');
const router = express.Router();
router.get('/test035', (req, res) => {
    const token = req.query.token;
    const html = '<script>document.write("Token: ' + token + '")</script>';
    res.send(html);
});
module.exports = router;
