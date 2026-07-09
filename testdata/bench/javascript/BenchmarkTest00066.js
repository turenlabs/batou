// Safe: Path traversal prevented via allowlist of files
const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const ALLOWED_FILES = ['report.pdf', 'summary.csv', 'data.json'];
router.get('/test066', (req, res) => {
    const filename = req.query.file;
    if (!ALLOWED_FILES.includes(filename)) {
        return res.status(403).send('File not allowed');
    }
    const filePath = path.join('/data', filename);
    fs.createReadStream(filePath).pipe(res);
});
module.exports = router;
