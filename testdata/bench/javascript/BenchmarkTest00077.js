// Vulnerable: Path traversal via fs.writeFileSync
const express = require('express');
const fs = require('fs');
const router = express.Router();
router.post('/test077', (req, res) => {
    const name = req.body.name;
    const data = req.body.data;
    fs.writeFileSync('/tmp/reports/' + name, data);
    res.send('Report saved');
});
module.exports = router;
