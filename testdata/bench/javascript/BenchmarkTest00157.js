// Vulnerable: SSTI via Handlebars compile from cookie
const express = require('express');
const Handlebars = require('handlebars');
const router = express.Router();
router.get('/test157', (req, res) => {
    const tpl = req.cookies.template;
    const compiled = Handlebars.compile(tpl);
    res.send(compiled({ data: 'test' }));
});
module.exports = router;
