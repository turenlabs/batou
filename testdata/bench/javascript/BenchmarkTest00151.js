// Vulnerable: SSTI via template literal evaluation
const express = require('express');
const router = express.Router();
router.post('/test151', (req, res) => {
    const tpl = req.body.template;
    const fn = new Function('data', 'return `' + tpl + '`');
    const result = fn({ name: 'test' });
    res.send(result);
});
module.exports = router;
