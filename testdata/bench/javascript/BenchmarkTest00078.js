// Safe: Path traversal prevented via UUID filename
const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const router = express.Router();
router.post('/test078', (req, res) => {
    const data = req.body.data;
    const safeName = crypto.randomUUID() + '.txt';
    fs.writeFileSync(path.join('/tmp/reports', safeName), data);
    res.json({ filename: safeName });
});
module.exports = router;
