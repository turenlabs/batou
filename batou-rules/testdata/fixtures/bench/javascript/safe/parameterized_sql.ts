import { Request, Response } from 'express';
import { Pool } from 'pg';
import knex from 'knex';

const pool = new Pool();
const db = knex({ client: 'pg' });

// SAFE: Parameterized query with pg pool - uses $1 placeholder
export async function getUserById(req: Request, res: Response): Promise<void> {
  const userId = req.params.id;
  const result = await pool.query(
    'SELECT id, name, email FROM users WHERE id = $1 AND deleted_at IS NULL',
    [userId]
  );
  res.json(result.rows);
}

// SAFE: Knex query builder - automatically parameterized
export async function searchProducts(req: Request, res: Response): Promise<void> {
  const term = req.query.q as string;
  const category = req.query.category as string;

  const products = await db('products')
    .select('id', 'name', 'price', 'description')
    .where('name', 'ilike', '%' + term + '%')
    .andWhere('category', category)
    .andWhere('active', true)
    .orderBy('name')
    .limit(50);

  res.json({ data: products });
}

// SAFE: Multi-parameter query with pg - all placeholders
export async function getOrderHistory(req: Request, res: Response): Promise<void> {
  const userId = req.query.userId as string;
  const status = req.query.status as string;
  const limit = parseInt(req.query.limit as string, 10) || 20;

  const { rows } = await pool.query(
    'SELECT o.id, o.total, o.status, o.created_at FROM orders o WHERE o.user_id = $1 AND o.status = $2 ORDER BY o.created_at DESC LIMIT $3',
    [userId, status, limit]
  );

  res.json(rows);
}

// SAFE: INSERT with parameterized query
export async function createUser(req: Request, res: Response): Promise<void> {
  const { name, email } = req.body;
  const result = await pool.query(
    'INSERT INTO users (name, email, created_at) VALUES ($1, $2, NOW()) RETURNING id',
    [name, email]
  );
  res.status(201).json({ id: result.rows[0].id });
}

// SAFE: UPDATE with parameterized query
export async function updateProfile(req: Request, res: Response): Promise<void> {
  const userId = req.params.id;
  const { displayName, bio } = req.body;
  await pool.query(
    'UPDATE profiles SET display_name = $1, bio = $2, updated_at = NOW() WHERE user_id = $3',
    [displayName, bio, userId]
  );
  res.json({ success: true });
}

// SAFE: DELETE with parameterized query
export async function deleteComment(req: Request, res: Response): Promise<void> {
  const commentId = req.params.commentId;
  const userId = req.query.userId as string;
  await pool.query(
    'DELETE FROM comments WHERE id = $1 AND author_id = $2',
    [commentId, userId]
  );
  res.status(204).send();
}
