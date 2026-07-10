// Safe: Path traversal prevented via path.resolve + startsWith check
const express = require('express');
const path = require('path');
const router = express.Router();
const DOCS_DIR = '/var/documents';
router.get('/test064', (req, res) => {
    const doc = req.query.doc;
    const resolved = path.resolve(DOCS_DIR, doc);
    if (!resolved.startsWith(DOCS_DIR)) {
        return res.status(403).send('Access denied');
    }
    res.sendFile(resolved);
});
module.exports = router;
