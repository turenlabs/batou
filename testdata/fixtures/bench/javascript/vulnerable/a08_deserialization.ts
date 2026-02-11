// Source: CVE-2017-5941 - node-serialize RCE
// Expected: GTSS-GEN-002 (Unsafe Deserialization)
// OWASP: A08:2021 - Software and Data Integrity Failures

import { Request, Response } from 'express';
import serialize from 'node-serialize';

export function loadSession(req: Request, res: Response): void {
  const sessionCookie = req.cookies.session;
  if (!sessionCookie) {
    res.status(401).json({ error: 'No session' });
    return;
  }
  const decoded = Buffer.from(sessionCookie, 'base64').toString();
  const sessionData = serialize.unserialize(decoded);
  res.json({ user: sessionData.username, role: sessionData.role });
}

export function importConfig(req: Request, res: Response): void {
  const configStr = req.body.config;
  const config = JSON.parse(configStr);
  res.json({ status: 'Config loaded', keys: Object.keys(config) });
}
