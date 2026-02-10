import { Request, Response } from 'express';
import { Sequelize, QueryTypes } from 'sequelize';
import mysql from 'mysql2/promise';

const sequelize = new Sequelize('sqlite::memory:');

// SAFE: Parameterized query using Sequelize replacements
export async function searchProducts(req: Request, res: Response): Promise<void> {
  const criteria = req.query.q as string;

  // SAFE: Uses parameterized query with bind parameters
  const products = await sequelize.query(
    'SELECT * FROM Products WHERE (name LIKE :search OR description LIKE :search) AND deletedAt IS NULL ORDER BY name',
    {
      replacements: { search: `%${criteria}%` },
      type: QueryTypes.SELECT,
    }
  );

  res.json({ status: 'success', data: products });
}

// SAFE: Parameterized query with mysql2 placeholders
export async function getUserById(pool: mysql.Pool, req: Request, res: Response): Promise<void> {
  const userId = req.params.id;

  // SAFE: Uses ? placeholder for parameterized queries
  const [rows] = await pool.query(
    'SELECT * FROM Users WHERE id = ?',
    [userId]
  );

  res.json(rows);
}

// SAFE: Sequelize ORM methods (automatically parameterized)
export async function findUserByEmail(req: Request, res: Response): Promise<void> {
  const email = req.body.email;

  // SAFE: Sequelize ORM where clause handles parameterization
  const user = await sequelize.query(
    'SELECT * FROM Users WHERE email = ?',
    { replacements: [email], type: QueryTypes.SELECT }
  );

  res.json(user);
}
