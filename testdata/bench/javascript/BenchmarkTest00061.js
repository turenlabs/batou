// Vulnerable: Path traversal via fs.readFile with user input
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.get('/test061', (req, res) => {
    const filename = req.query.file;
    fs.readFile('/uploads/' + filename, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});
module.exports = router;
