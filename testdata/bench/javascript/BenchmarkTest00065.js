// Vulnerable: Path traversal via fs.createReadStream
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.get('/test065', (req, res) => {
    const filePath = req.query.path;
    const stream = fs.createReadStream('/data/' + filePath);
    stream.pipe(res);
});
module.exports = router;
