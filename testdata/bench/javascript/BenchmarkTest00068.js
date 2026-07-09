// Safe: Path traversal prevented via path.normalize + check
const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
router.post('/test068', (req, res) => {
    const filename = req.body.filename;
    const content = req.body.content;
    const normalized = path.normalize(filename);
    if (normalized.includes('..')) {
        return res.status(400).send('Invalid filename');
    }
    const safePath = path.join('/uploads', path.basename(normalized));
    fs.writeFile(safePath, content, (err) => {
        if (err) return res.status(500).send('Write failed');
        res.send('File saved');
    });
});
module.exports = router;
