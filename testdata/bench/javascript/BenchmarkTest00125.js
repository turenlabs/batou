// Vulnerable: Deserialization via new Function construction
const express = require('express');
const router = express.Router();
router.post('/test125', (req, res) => {
    const code = req.body.transform;
    const fn = new Function('data', code);
    const result = fn({ items: [1, 2, 3] });
    res.json({ result });
});
module.exports = router;
