// Safe: SSTI prevented via fixed Pug template file
const express = require('express');
const path = require('path');
const router = express.Router();
router.post('/test144', (req, res) => {
    const name = req.body.name;
    res.render('greeting', { name });
});
module.exports = router;
