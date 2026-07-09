// Vulnerable: Path traversal via res.sendFile
const express = require('express');
const router = express.Router();
router.get('/test063', (req, res) => {
    const doc = req.query.doc;
    res.sendFile('/var/documents/' + doc);
});
module.exports = router;
