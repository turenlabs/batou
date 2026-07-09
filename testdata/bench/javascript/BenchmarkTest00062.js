// Safe: Path traversal prevented via path.basename
const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
router.get('/test062', (req, res) => {
    const filename = req.query.file;
    const safeName = path.basename(filename);
    fs.readFile(path.join('/uploads', safeName), 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});
module.exports = router;
