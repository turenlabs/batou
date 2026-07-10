// Safe: Path traversal prevented via basename + existence check
const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
router.delete('/test080', (req, res) => {
    const file = req.query.file;
    const safePath = path.join('/uploads', path.basename(file));
    if (!fs.existsSync(safePath)) {
        return res.status(404).send('File not found');
    }
    fs.unlink(safePath, (err) => {
        if (err) return res.status(500).send('Delete failed');
        res.send('Deleted');
    });
});
module.exports = router;
