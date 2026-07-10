// Vulnerable: Deserialization via node-serialize unserialize
const express = require('express');
const serialize = require('node-serialize');
const router = express.Router();
router.post('/test123', (req, res) => {
    const data = req.body.data;
    const obj = serialize.unserialize(data);
    res.json(obj);
});
module.exports = router;
