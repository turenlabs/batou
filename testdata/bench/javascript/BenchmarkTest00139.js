// Vulnerable: Deserialization via vm.Script with user code
const express = require('express');
const vm = require('vm');
const router = express.Router();
router.post('/test139', (req, res) => {
    const code = req.body.code;
    const script = new vm.Script(code);
    const result = script.runInNewContext({ data: [1, 2, 3] });
    res.json({ result });
});
module.exports = router;
