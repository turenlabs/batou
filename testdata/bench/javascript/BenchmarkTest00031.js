// Vulnerable: Reflected XSS via req.params in template
const express = require('express');
const router = express.Router();
router.get('/user/:name', (req, res) => {
    const name = req.params.name;
    res.send('<html><body><h1>Profile: ' + name + '</h1></body></html>');
});
module.exports = router;
