// Vulnerable: Command injection via req.params in shell command
const express = require('express');
const { exec } = require('child_process');
const router = express.Router();
router.get('/logs/:service', (req, res) => {
    const service = req.params.service;
    exec('journalctl -u ' + service + ' --no-pager', (err, stdout) => {
        res.send('<pre>' + stdout + '</pre>');
    });
});
module.exports = router;
