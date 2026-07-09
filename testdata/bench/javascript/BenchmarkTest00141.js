// Vulnerable: SSTI via EJS render with user-controlled template
const express = require('express');
const ejs = require('ejs');
const router = express.Router();
router.post('/test141', (req, res) => {
    const template = req.body.template;
    const html = ejs.render(template, { user: 'admin' });
    res.send(html);
});
module.exports = router;
