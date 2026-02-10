import { Request, Response } from 'express';
import mongoose from 'mongoose';

const ProductSchema = new mongoose.Schema({
  name: String,
  price: Number,
  description: String,
  category: String,
});
const Product = mongoose.model('Product', ProductSchema);

// VULNERABLE: Direct use of req.body without any validation
export async function createProduct(req: Request, res: Response): Promise<void> {
  // VULNERABLE: req.body.name used without validation or sanitization
  const name = req.body.name;
  const price = req.body.price;
  const description = req.body.description;

  // No length check, no type check, no sanitization
  const product = await Product.create({ name, price, description });
  res.status(201).json(product);
}

// VULNERABLE: parseInt without NaN check
export async function getProductById(req: Request, res: Response): Promise<void> {
  // VULNERABLE: parseInt on req.params without NaN validation
  const id = parseInt(req.params.id);

  // If id is NaN, this could cause unexpected behavior
  const product = await Product.findById(id);
  res.json(product);
}

// VULNERABLE: Dynamic property access with user input, no allowlist
export async function updateField(req: Request, res: Response): Promise<void> {
  const field = req.body.field;
  const value = req.body.value;
  const productId = req.params.id;

  // VULNERABLE: user controls which field gets updated - no allowlist
  const update: any = {};
  update[req.body.field] = value;

  await Product.findByIdAndUpdate(productId, update);
  res.json({ status: 'updated' });
}
