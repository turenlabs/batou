// Safe: Command injection prevented via execFile (no shell)
const express = require('express');
const { execFile } = require('child_process');
const router = express.Router();
router.get('/logs/:service', (req, res) => {
    const service = req.params.service;
    execFile('journalctl', ['-u', service, '--no-pager'], (err, stdout) => {
        res.send('<pre>' + stdout + '</pre>');
    });
});
module.exports = router;
