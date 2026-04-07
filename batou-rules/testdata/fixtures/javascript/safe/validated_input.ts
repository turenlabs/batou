import { Request, Response } from 'express';
import Joi from 'joi';
import mongoose from 'mongoose';

const ProductSchema = new mongoose.Schema({
  name: String,
  price: Number,
  description: String,
  category: String,
});
const Product = mongoose.model('Product', ProductSchema);

// SAFE: Joi schema validation before any use of request data
const createProductSchema = Joi.object({
  name: Joi.string().min(1).max(255).required().trim(),
  price: Joi.number().positive().max(999999).required(),
  description: Joi.string().max(2000).optional().trim(),
  category: Joi.string().valid('electronics', 'books', 'clothing', 'food').required(),
});

export async function createProduct(req: Request, res: Response): Promise<void> {
  // SAFE: Validate input with Joi schema
  const { error, value } = createProductSchema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true, // SAFE: strip unknown fields (prevents mass assignment)
  });

  if (error) {
    res.status(400).json({
      error: 'Validation failed',
      details: error.details.map(d => d.message),
    });
    return;
  }

  // SAFE: Use validated and sanitized data
  const product = await Product.create(value);
  res.status(201).json(product);
}

// SAFE: parseInt with isNaN check
export async function getProductById(req: Request, res: Response): Promise<void> {
  const id = parseInt(req.params.id, 10);

  // SAFE: Check for NaN after parseInt
  if (isNaN(id) || id <= 0) {
    res.status(400).json({ error: 'Invalid product ID' });
    return;
  }

  const product = await Product.findById(id);
  if (!product) {
    res.status(404).json({ error: 'Product not found' });
    return;
  }

  res.json(product);
}

// SAFE: Allowlist for updatable fields
const ALLOWED_UPDATE_FIELDS = ['name', 'price', 'description', 'category'];

export async function updateField(req: Request, res: Response): Promise<void> {
  const field = req.body.field;
  const value = req.body.value;

  // SAFE: Check field against allowlist
  if (!ALLOWED_UPDATE_FIELDS.includes(field)) {
    res.status(400).json({ error: 'Field not updatable' });
    return;
  }

  const update: Record<string, any> = {};
  update[field] = value;

  await Product.findByIdAndUpdate(req.params.id, update);
  res.json({ status: 'updated' });
}
