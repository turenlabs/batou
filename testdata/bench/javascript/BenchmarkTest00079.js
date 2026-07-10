// Vulnerable: Path traversal via fs.unlink
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.delete('/test079', (req, res) => {
    const file = req.query.file;
    fs.unlink('/uploads/' + file, (err) => {
        if (err) return res.status(500).send('Delete failed');
        res.send('Deleted');
    });
});
module.exports = router;
