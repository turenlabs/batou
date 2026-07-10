// Vulnerable: SSTI via Handlebars compile with user template
const express = require('express');
const Handlebars = require('handlebars');
const router = express.Router();
router.post('/test145', (req, res) => {
    const templateSrc = req.body.template;
    const compiled = Handlebars.compile(templateSrc);
    const html = compiled({ name: 'World' });
    res.send(html);
});
module.exports = router;
