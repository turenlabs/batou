// Vulnerable: Code execution via vm.runInNewContext with user input
const express = require('express');
const vm = require('vm');
const router = express.Router();
router.post('/test129', (req, res) => {
    const expression = req.body.expr;
    const result = vm.runInNewContext(expression, { Math, Date });
    res.json({ result });
});
module.exports = router;
