// Vulnerable: Deserialization via eval of user string
const express = require('express');
const router = express.Router();
router.post('/test131', (req, res) => {
    const input = req.body.data;
    const obj = eval('(' + input + ')');
    res.json(obj);
});
module.exports = router;
