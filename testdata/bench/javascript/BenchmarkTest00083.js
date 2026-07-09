// Vulnerable: SSRF via axios.get with user input
const express = require('express');
const axios = require('axios');
const router = express.Router();
router.get('/test083', async (req, res) => {
    const target = req.query.target;
    const response = await axios.get(target);
    res.json(response.data);
});
module.exports = router;
