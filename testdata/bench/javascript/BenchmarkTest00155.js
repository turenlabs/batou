// Vulnerable: SSTI via EJS from header value
const express = require('express');
const ejs = require('ejs');
const router = express.Router();
router.get('/test155', (req, res) => {
    const greeting = req.headers['x-custom-template'];
    const html = ejs.render(greeting, { user: 'guest' });
    res.send(html);
});
module.exports = router;
