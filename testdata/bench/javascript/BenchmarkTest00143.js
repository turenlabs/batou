// Vulnerable: SSTI via Pug render with user template string
const express = require('express');
const pug = require('pug');
const router = express.Router();
router.post('/test143', (req, res) => {
    const markup = req.body.markup;
    const html = pug.render(markup);
    res.send(html);
});
module.exports = router;
