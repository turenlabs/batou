// Safe: SSTI prevented via pre-compiled Handlebars template
const express = require('express');
const Handlebars = require('handlebars');
const router = express.Router();
const template = Handlebars.compile('<h1>Hello {{name}}</h1>');
router.post('/test146', (req, res) => {
    const name = req.body.name;
    const html = template({ name });
    res.send(html);
});
module.exports = router;
