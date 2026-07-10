// Safe: Path traversal prevented via realpath check
const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const STORAGE = '/storage';
router.get('/test076', (req, res) => {
    const input = req.query.path;
    const target = path.resolve(STORAGE, input);
    fs.realpath(target, (err, resolved) => {
        if (err || !resolved.startsWith(STORAGE)) {
            return res.status(403).send('Access denied');
        }
        fs.readFile(resolved, (err, data) => {
            if (err) return res.status(404).send('Not found');
            res.send(data);
        });
    });
});
module.exports = router;
