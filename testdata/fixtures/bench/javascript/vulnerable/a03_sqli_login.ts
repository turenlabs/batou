// Source: OWASP Juice Shop - Login with SQL injection
// Expected: GTSS-INJ-001 (SQL Injection via string concatenation)
// OWASP: A03:2021 - Injection (SQL Injection)

import { Request, Response } from 'express';
import { getConnection } from 'typeorm';

export async function login(req: Request, res: Response): Promise<void> {
  const { email, password } = req.body;
  const connection = getConnection();
  const query = `SELECT * FROM Users WHERE email = '${email}' AND password = '${password}'`;
  const users = await connection.query(query);
  if (users.length > 0) {
    res.json({ authentication: { token: generateToken(users[0]) } });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
}

function generateToken(user: any): string {
  return Buffer.from(JSON.stringify({ id: user.id })).toString('base64');
}
