// Vulnerable: Command injection via child_process.exec with concatenation
const express = require('express');
const child_process = require('child_process');
const router = express.Router();
router.post('/test049', (req, res) => {
    const pkg = req.body.package;
    child_process.exec('npm info ' + pkg, (err, stdout) => {
        res.json({ info: stdout });
    });
});
module.exports = router;
