import { Request, Response } from 'express';
import { Sequelize } from 'sequelize';

const sequelize = new Sequelize('sqlite::memory:');

// Juice Shop style: search products with string concatenation SQL injection
export async function searchProducts(req: Request, res: Response): Promise<void> {
  const criteria = req.query.q as string;

  // VULNERABLE: SQL injection via string concatenation in .query()
  const products = await sequelize.query(
    "SELECT * FROM Products WHERE ((name LIKE '%" + criteria + "%' OR description LIKE '%" + criteria + "%') AND deletedAt IS NULL) ORDER BY name"
  );

  res.json({ status: 'success', data: products });
}

export async function getUserById(req: Request, res: Response): Promise<void> {
  const userId = req.params.id;

  // VULNERABLE: SQL injection via string concatenation with SELECT
  const result = await sequelize.query("SELECT * FROM Users WHERE id = " + userId);
  res.json(result);
}
