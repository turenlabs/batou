// Vulnerable: Code injection via vm.runInContext
const express = require('express');
const vm = require('vm');
const router = express.Router();
router.post('/test135', (req, res) => {
    const script = req.body.script;
    const context = vm.createContext({ console });
    vm.runInContext(script, context);
    res.json({ status: 'executed' });
});
module.exports = router;
