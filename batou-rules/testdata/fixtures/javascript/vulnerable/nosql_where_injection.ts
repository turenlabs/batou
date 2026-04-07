import { Request, Response } from 'express';
import mongoose from 'mongoose';

const OrderSchema = new mongoose.Schema({ orderId: String, email: String, total: Number });
const Order = mongoose.model('Order', OrderSchema);

// VULNERABLE: $where with template literal interpolation (Juice Shop trackOrder.ts pattern)
export async function trackOrder(req: Request, res: Response): Promise<void> {
  const id = req.params.id;
  const order = await Order.find({
    "$where": `this.orderId === '${id}'`
  });
  res.json({ order });
}

// VULNERABLE: $where with string concatenation
export async function searchOrders(req: Request, res: Response): Promise<void> {
  const term = req.query.search as string;
  const orders = await Order.find({
    "$where": "this.email.includes('" + term + "')"
  });
  res.json({ orders });
}
