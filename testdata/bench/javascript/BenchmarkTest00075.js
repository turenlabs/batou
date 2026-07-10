// Vulnerable: Path traversal via variable indirection
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.get('/test075', (req, res) => {
    const input = req.query.path;
    const target = input;
    const fullPath = '/storage/' + target;
    fs.readFile(fullPath, (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});
module.exports = router;
