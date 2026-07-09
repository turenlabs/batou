// Vulnerable: Deserialization via yaml.load (unsafe)
const express = require('express');
const yaml = require('js-yaml');
const router = express.Router();
router.post('/test127', (req, res) => {
    const yamlData = req.body.config;
    const config = yaml.load(yamlData);
    res.json(config);
});
module.exports = router;
