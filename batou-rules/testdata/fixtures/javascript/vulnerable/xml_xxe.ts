import { Request, Response } from 'express';
import { DOMParser } from 'xmldom';
import libxmljs from 'libxmljs';

// VULNERABLE: XML parsing with external entities not explicitly disabled
export function parseXMLOrder(req: Request, res: Response): void {
  const xmlInput = req.body.xml;

  // VULNERABLE: DOMParser without disabling external entities
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlInput, 'text/xml');

  const orderId = doc.getElementsByTagName('orderId')[0]?.textContent;
  const amount = doc.getElementsByTagName('amount')[0]?.textContent;

  res.json({ orderId, amount });
}

// VULNERABLE: libxmljs with noent: true enables entity expansion (XXE)
export function parseXMLConfig(req: Request, res: Response): void {
  const xmlData = req.body.config;

  // VULNERABLE: noent:true enables external entity resolution
  const doc = libxmljs.parseXml(xmlData, { noent: true, nonet: false });

  const dbHost = doc.get('//database/host')?.text();
  const dbPort = doc.get('//database/port')?.text();

  res.json({ dbHost, dbPort });
}

// VULNERABLE: template injection via ejs.render with user input
import ejs from 'ejs';

export function renderTemplate(req: Request, res: Response): void {
  const templateBody = req.body.template;

  // VULNERABLE: ejs.render with user-controlled template (SSTI)
  const html = ejs.render(templateBody, { user: { name: 'Test' } });
  res.send(html);
}
