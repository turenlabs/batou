import { Request, Response } from 'express';
import mysql from 'mysql2/promise';

let pool: mysql.Pool;

export async function initDB(): Promise<void> {
  pool = mysql.createPool({ host: 'localhost', user: 'app', database: 'shop' });
}

// VULNERABLE: SQL injection via template literal interpolation
export async function findUser(req: Request, res: Response): Promise<void> {
  const email = req.body.email;
  const password = req.body.password;

  const [rows] = await pool.query(
    `SELECT * FROM Users WHERE email = '${email}' AND password = '${password}'`
  );

  if ((rows as any[]).length === 0) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  res.json({ user: (rows as any[])[0] });
}

export async function deleteProduct(req: Request, res: Response): Promise<void> {
  const productId = req.params.id;

  // VULNERABLE: SQL injection via template literal with DELETE
  await pool.query(`DELETE FROM Products WHERE id = ${productId}`);
  res.status(204).end();
}
