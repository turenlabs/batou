// Safe: Command injection prevented via spawn without shell
const express = require('express');
const { spawn } = require('child_process');
const router = express.Router();
router.get('/test056', (req, res) => {
    const query = req.query.q;
    const proc = spawn('grep', [query, '/var/data/records.txt']);
    let output = '';
    proc.stdout.on('data', (data) => { output += data; });
    proc.on('close', () => { res.send(output); });
});
module.exports = router;
