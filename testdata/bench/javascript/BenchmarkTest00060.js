// Safe: Command injection prevented via URL validation + execFile
const express = require('express');
const { execFile } = require('child_process');
const router = express.Router();
router.post('/test060', (req, res) => {
    const repo = req.body.repo;
    try {
        const url = new URL(repo);
        if (url.protocol !== 'https:') throw new Error('Only HTTPS');
    } catch (e) {
        return res.status(400).json({ error: 'Invalid repo URL' });
    }
    execFile('git', ['clone', repo, '/tmp/checkout'], (err, stdout) => {
        res.json({ output: stdout });
    });
});
module.exports = router;
