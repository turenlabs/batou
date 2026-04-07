import { Request, Response } from 'express';
import mongoose from 'mongoose';

const Order = mongoose.model('Order');

// SAFE: $lookup with hardcoded collection name
export async function lookupOrders(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$lookup": { "from": "users", localField: "userId", foreignField: "_id", as: "userDetails" } }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}

// SAFE: $merge with hardcoded collection name
export async function mergeResults(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$group": { "_id": "$status", count: { "$sum": 1 } } },
    { "$merge": "order_summaries" }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}

// SAFE: $group with hardcoded field
export async function groupByStatus(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$group": { "_id": "$status", total: { "$sum": "$amount" } } }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}

// SAFE: $addFields with hardcoded expression
export async function addComputedFields(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$addFields": { "totalWithTax": { "$multiply": ["$amount", 1.1] } } }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}
