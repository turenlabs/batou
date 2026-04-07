// Source: PayloadsAllTheThings - Server-Side Template Injection
// Expected: BATOU-INJ-005 (Template Injection via compile/render with user input)
// OWASP: A03:2021 - Injection (Server-Side Template Injection)

import { Request, Response } from 'express';
import pug from 'pug';
import nunjucks from 'nunjucks';

export function renderTemplate(req: Request, res: Response): void {
  const template = req.body.template;
  const data = req.body.data || {};
  const compiledFn = pug.compile(template);
  const html = compiledFn(data);
  res.send(html);
}

export function renderEmail(req: Request, res: Response): void {
  const subject = req.body.subject;
  const body = req.body.body;
  const templateStr = `<h1>${subject}</h1><div>${body}</div>`;
  const result = nunjucks.renderString(templateStr, { user: req.body.user });
  res.send(result);
}
