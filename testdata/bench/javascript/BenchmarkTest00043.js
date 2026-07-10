// Vulnerable: Command injection via template literal in exec
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.post('/test043', (req, res) => {
    const host = req.body.host;
    exec(`ping -c 4 ${host}`, (err, stdout) => {
        res.send('<pre>' + stdout + '</pre>');
    });
});
module.exports = router;
