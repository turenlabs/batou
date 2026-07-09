// Vulnerable: Deserialization via variable indirection to eval
const express = require('express');
const router = express.Router();
router.post('/test137', (req, res) => {
    const rawInput = req.body.payload;
    const data = rawInput;
    const parsed = eval(data);
    res.json({ result: parsed });
});
module.exports = router;
