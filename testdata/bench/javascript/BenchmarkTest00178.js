// Safe: Redirect prevented via parameterized path only
const express = require('express');
const router = express.Router();
router.get('/test178', (req, res) => {
    const section = req.query.section;
    const allowed = ['overview', 'details', 'history'];
    if (!allowed.includes(section)) return res.redirect('/overview');
    res.redirect('/' + section);
});
module.exports = router;
