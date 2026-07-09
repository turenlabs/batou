// Vulnerable: Path traversal via params in fs.readFileSync
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.get('/templates/:name', (req, res) => {
    const name = req.params.name;
    const content = fs.readFileSync('/templates/' + name, 'utf8');
    res.send(content);
});
module.exports = router;
