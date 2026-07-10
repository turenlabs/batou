// Safe: Command injection prevented via execFile with args array
const express = require('express');
const { execFile } = require('child_process');
const router = express.Router();
router.get('/test042', (req, res) => {
    const filename = req.query.file;
    execFile('cat', ['/var/log/' + filename], (err, stdout) => {
        res.send(stdout);
    });
});
module.exports = router;
