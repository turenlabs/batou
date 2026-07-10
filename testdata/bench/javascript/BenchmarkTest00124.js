// Safe: Deserialization via JSON with schema validation
const express = require('express');
const Ajv = require('ajv');
const router = express.Router();
const ajv = new Ajv();
const schema = { type: 'object', properties: { name: { type: 'string' }, age: { type: 'number' } } };
router.post('/test124', (req, res) => {
    const valid = ajv.validate(schema, req.body);
    if (!valid) return res.status(400).json({ error: ajv.errorsText() });
    res.json(req.body);
});
module.exports = router;
