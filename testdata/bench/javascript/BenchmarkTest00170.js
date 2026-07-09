// Safe: Redirect prevented via encodeURIComponent in path
const express = require('express');
const router = express.Router();
router.get('/test170', (req, res) => {
    const page = req.query.page;
    const safePage = encodeURIComponent(page);
    res.redirect('/pages/' + safePage);
});
module.exports = router;
