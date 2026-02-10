import { Request, Response } from 'express';
import vm from 'vm';

// Juice Shop style: insecure deserialization via eval and vm
export function processB2BOrder(req: Request, res: Response): void {
  const orderData = req.body.orderLinesData;

  // VULNERABLE: eval with user-controlled input (code injection)
  const parsed = eval(orderData);

  res.json({ status: 'processed', items: parsed.length });
}

// VULNERABLE: new Function constructor with user data
export function computeDiscount(req: Request, res: Response): void {
  const formula = req.body.discountFormula;

  const calculate = new Function('price', 'quantity', formula);
  const result = calculate(100, 5);

  res.json({ discount: result });
}

// VULNERABLE: setTimeout with string argument (implicit eval)
export function scheduleJob(req: Request, res: Response): void {
  const taskCode = req.body.task;

  // VULNERABLE: setTimeout with string - this is equivalent to eval()
  setTimeout("processTask('" + taskCode + "')", 1000);
  res.json({ status: 'scheduled' });
}

// VULNERABLE: vm.runInNewContext with user data
export function runSandboxedCode(req: Request, res: Response): void {
  const userCode = req.body.expression;

  const result = vm.runInNewContext(userCode, { Math, Date });
  res.json({ result });
}
