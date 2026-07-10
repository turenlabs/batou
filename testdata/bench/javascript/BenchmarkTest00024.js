// Safe: XSS prevented via DOMPurify sanitization
const express = require('express');
const DOMPurify = require('dompurify');
const router = express.Router();
router.get('/test024', (req, res) => {
    const comment = req.body.comment;
    const clean = DOMPurify.sanitize(comment);
    res.send('<div class="comment">' + clean + '</div>');
});
module.exports = router;
