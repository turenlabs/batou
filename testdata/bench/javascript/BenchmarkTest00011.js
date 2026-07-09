// Vulnerable: SQL injection via Prisma $queryRawUnsafe
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const router = express.Router();
router.get('/test011', async (req, res) => {
    const email = req.query.email;
    const users = await prisma.$queryRawUnsafe("SELECT * FROM users WHERE email = '" + email + "'");
    res.json(users);
});
module.exports = router;
