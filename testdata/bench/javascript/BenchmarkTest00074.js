// Safe: Path traversal prevented via sendFile with root option
const express = require('express');
const router = express.Router();
router.get('/templates/:name', (req, res) => {
    const name = req.params.name;
    res.sendFile(name, { root: '/templates' }, (err) => {
        if (err) res.status(404).send('Not found');
    });
});
module.exports = router;
