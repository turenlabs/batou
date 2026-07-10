// Vulnerable: Code injection via setTimeout with string
const express = require('express');
const router = express.Router();
router.post('/test133', (req, res) => {
    const action = req.body.action;
    const delay = req.body.delay || 1000;
    setTimeout('console.log("' + action + '")', delay);
    res.json({ status: 'scheduled' });
});
module.exports = router;
