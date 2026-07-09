// Vulnerable: Path traversal via fs.writeFile
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.post('/test067', (req, res) => {
    const filename = req.body.filename;
    const content = req.body.content;
    fs.writeFile('/uploads/' + filename, content, (err) => {
        if (err) return res.status(500).send('Write failed');
        res.send('File saved');
    });
});
module.exports = router;
