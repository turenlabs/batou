// Safe: XSS prevented via sanitize-html library
const express = require('express');
const sanitizeHtml = require('sanitize-html');
const router = express.Router();
router.get('/test032', (req, res) => {
    const content = req.query.content;
    const clean = sanitizeHtml(content, { allowedTags: [] });
    res.send('<p>' + clean + '</p>');
});
module.exports = router;
