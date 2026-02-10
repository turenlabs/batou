import { Request, Response } from 'express';
import { XMLParser } from 'fast-xml-parser';

// SAFE: XML parsing with external entities disabled
export function parseXMLOrder(req: Request, res: Response): void {
  const xmlInput = req.body.xml;

  // SAFE: fast-xml-parser does not support external entity resolution by default
  const parser = new XMLParser({
    ignoreAttributes: false,
    allowBooleanAttributes: true,
    parseTagValue: true,
    trimValues: true,
  });

  try {
    const result = parser.parse(xmlInput);
    const orderId = result?.order?.orderId;
    const amount = result?.order?.amount;

    if (!orderId || !amount) {
      res.status(400).json({ error: 'Missing required fields' });
      return;
    }

    res.json({ orderId, amount });
  } catch (err) {
    res.status(400).json({ error: 'Invalid XML' });
  }
}

// SAFE: Using JSON instead of XML for data exchange
export function parseOrderJSON(req: Request, res: Response): void {
  const { orderId, amount, items } = req.body;

  // SAFE: JSON parsing is not vulnerable to XXE
  if (!orderId || typeof amount !== 'number' || !Array.isArray(items)) {
    res.status(400).json({ error: 'Invalid order data' });
    return;
  }

  res.json({ orderId, amount, itemCount: items.length });
}

// SAFE: Template rendering with predefined template name (not user-controlled)
export function renderReceipt(req: Request, res: Response): void {
  const orderData = req.body;

  // SAFE: Template name is a string literal, not user-controlled
  res.render('receipt', {
    orderId: orderData.orderId,
    amount: orderData.amount,
    date: new Date().toISOString(),
  });
}
