import { Request, Response } from 'express';
import * as vm from 'vm';

// Juice Shop b2bOrder.ts style: vm.runInContext with user-controlled code
// This is a full RCE vulnerability — the Node.js vm module is NOT a security sandbox.

interface B2BOrder {
  orderLinesData: string;
}

export function processB2BOrder(req: Request, res: Response): void {
  const order: B2BOrder = req.body;

  // VULNERABLE: User-controlled data passed directly to vm.runInContext
  // An attacker can escape the sandbox and execute arbitrary code:
  //   orderLinesData: "this.constructor.constructor('return process')().exit()"
  const sandbox = { safeEval: (code: string) => code };
  const ctx = vm.createContext(sandbox);
  const result = vm.runInContext('safeEval(orderLinesData)', ctx);

  res.json({ processed: result });
}

export function evaluateExpression(req: Request, res: Response): void {
  const expr = req.query.expr as string;

  // VULNERABLE: vm.runInNewContext with user input
  const result = vm.runInNewContext(expr, { Math, parseInt });

  res.json({ result });
}

export function runUserScript(req: Request, res: Response): void {
  const code = req.body.code;

  // VULNERABLE: new Function() constructor with user-controlled code
  const fn = new Function('input', code);
  const output = fn(req.body.input);

  res.json({ output });
}
