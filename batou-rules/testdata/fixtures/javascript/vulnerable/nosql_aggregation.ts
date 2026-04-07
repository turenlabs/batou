import { Request, Response } from 'express';
import mongoose from 'mongoose';

const Order = mongoose.model('Order');

// VULNERABLE: $lookup with user-controlled "from" collection
export async function lookupOrders(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$lookup": { "from": req.body.collection, localField: "userId", foreignField: "_id", as: "details" } }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}

// VULNERABLE: $merge with user-controlled collection name
export async function mergeResults(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$group": { "_id": "$status", count: { "$sum": 1 } } },
    { "$merge": req.body.targetCollection }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}

// VULNERABLE: $out with user-controlled collection name
export async function exportData(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$match": { status: "completed" } },
    { "$out": req.query.outputCollection }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}

// VULNERABLE: $group with user-controlled _id expression
export async function groupBy(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$group": { "_id": req.body.groupField, total: { "$sum": "$amount" } } }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}

// VULNERABLE: $addFields with user-controlled expression
export async function addFields(req: Request, res: Response): Promise<void> {
  const pipeline = [
    { "$addFields": req.body.newFields }
  ];
  const results = await Order.aggregate(pipeline);
  res.json(results);
}
