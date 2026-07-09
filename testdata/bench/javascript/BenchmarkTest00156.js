// Safe: SSTI prevented via static template with escaped data
const express = require('express');
const ejs = require('ejs');
const router = express.Router();
const TEMPLATE = '<p>Welcome, <%- user %></p>';
router.get('/test156', (req, res) => {
    const user = req.query.user || 'Guest';
    const html = ejs.render(TEMPLATE, { user: String(user).replace(/[<>&"']/g, '') });
    res.send(html);
});
module.exports = router;
