// Safe: Deserialization via structured clone / JSON round-trip
const express = require('express');
const router = express.Router();
router.post('/test132', (req, res) => {
    const input = req.body.data;
    const safe = JSON.parse(JSON.stringify(input));
    res.json(safe);
});
module.exports = router;
