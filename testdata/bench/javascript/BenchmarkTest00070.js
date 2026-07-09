// Safe: Path traversal prevented via regex validation
const express = require('express');
const path = require('path');
const router = express.Router();
router.get('/test070', (req, res) => {
    const file = req.query.file;
    if (!/^[a-zA-Z0-9._-]+$/.test(file)) {
        return res.status(400).send('Invalid filename');
    }
    res.download(path.join('/exports', file));
});
module.exports = router;
