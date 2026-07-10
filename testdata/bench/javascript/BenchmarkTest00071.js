// Vulnerable: Path traversal via template literal in readFile
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.get('/test071', (req, res) => {
    const id = req.query.id;
    const configPath = `/configs/${id}/settings.json`;
    fs.readFile(configPath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.json(JSON.parse(data));
    });
});
module.exports = router;
