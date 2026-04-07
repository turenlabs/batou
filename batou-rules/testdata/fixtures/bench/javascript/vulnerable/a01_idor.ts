// Source: OWASP Juice Shop - Basket access without authorization
// Expected: BATOU-INJ-007 (NoSQL Injection), BATOU-VAL-001 (Direct Request Parameter Usage)
// OWASP: A01:2021 - Broken Access Control (IDOR)

import { Request, Response } from 'express';
import { getRepository } from 'typeorm';
import { Basket } from '../models/Basket';

export async function getBasket(req: Request, res: Response): Promise<void> {
  const basketId = req.params.id;
  const repo = getRepository(Basket);
  const basket = await repo.findOne({ where: { id: basketId } });
  if (!basket) {
    res.status(404).json({ error: 'Basket not found' });
    return;
  }
  res.json(basket);
}

export async function updateBasket(req: Request, res: Response): Promise<void> {
  const basketId = req.params.id;
  const repo = getRepository(Basket);
  await repo.update(basketId, req.body);
  res.json({ status: 'success' });
}
