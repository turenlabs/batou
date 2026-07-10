// Vulnerable: SSTI via Pug with user content in compile
const express = require('express');
const pug = require('pug');
const router = express.Router();
router.post('/test153', (req, res) => {
    const layout = req.body.layout;
    const compileFn = pug.compile(layout);
    const html = compileFn({ title: 'Dashboard' });
    res.send(html);
});
module.exports = router;
