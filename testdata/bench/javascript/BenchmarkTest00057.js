// Vulnerable: Command injection in async/await pattern
const express = require('express');
const util = require('util');
const exec = util.promisify(require('child_process').exec);
const router = express.Router();
router.get('/test057', async (req, res) => {
    const ip = req.query.ip;
    const { stdout } = await exec('nslookup ' + ip);
    res.send(stdout);
});
module.exports = router;
