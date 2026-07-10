// Vulnerable: Deserialization via eval of parsed JSON
const express = require('express');
const router = express.Router();
router.post('/test121', (req, res) => {
    const data = req.body.code;
    const result = eval(data);
    res.json({ result });
});
module.exports = router;
