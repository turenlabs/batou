// Safe: Deserialization via yaml.safeLoad
const express = require('express');
const yaml = require('js-yaml');
const router = express.Router();
router.post('/test128', (req, res) => {
    const yamlData = req.body.config;
    try {
        const config = yaml.safeLoad(yamlData);
        res.json(config);
    } catch (e) {
        res.status(400).json({ error: 'Invalid YAML' });
    }
});
module.exports = router;
