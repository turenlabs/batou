// Vulnerable: SSTI via EJS with variable indirection
const express = require('express');
const ejs = require('ejs');
const router = express.Router();
router.post('/test149', (req, res) => {
    const input = req.body.content;
    const tpl = input;
    const result = ejs.render(tpl, { items: [1, 2, 3] });
    res.send(result);
});
module.exports = router;
