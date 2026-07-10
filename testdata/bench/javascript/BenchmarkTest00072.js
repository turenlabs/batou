// Safe: Path traversal prevented via parseInt for numeric path
const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
router.get('/test072', (req, res) => {
    const id = parseInt(req.query.id, 10);
    if (isNaN(id) || id < 1) {
        return res.status(400).send('Invalid ID');
    }
    const configPath = path.join('/configs', String(id), 'settings.json');
    fs.readFile(configPath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.json(JSON.parse(data));
    });
});
module.exports = router;
