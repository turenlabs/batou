// Safe: Code execution prevented via static script
const express = require('express');
const vm = require('vm');
const router = express.Router();
const SAFE_SCRIPT = new vm.Script('result = data.reduce((a, b) => a + b, 0)');
router.post('/test140', (req, res) => {
    const data = (req.body.data || []).map(Number).filter(n => !isNaN(n));
    const ctx = { data, result: null };
    SAFE_SCRIPT.runInNewContext(ctx);
    res.json({ result: ctx.result });
});
module.exports = router;
