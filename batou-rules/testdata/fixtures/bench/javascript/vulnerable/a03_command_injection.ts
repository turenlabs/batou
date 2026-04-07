// Source: CVE-2019-10758 - mongo-express remote code execution
// Expected: BATOU-INJ-002 (Command Injection via exec/spawn)
// OWASP: A03:2021 - Injection (OS Command Injection)

import { Request, Response } from 'express';
import { exec } from 'child_process';

export function convertImage(req: Request, res: Response): void {
  const inputFile = req.query.file as string;
  const format = req.query.format as string;
  const outputFile = inputFile.replace(/\.\w+$/, `.${format}`);
  exec(`convert ${inputFile} ${outputFile}`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
      return;
    }
    res.json({ output: outputFile });
  });
}

export function pingHost(req: Request, res: Response): void {
  const host = req.params.host;
  exec(`ping -c 4 ${host}`, (error, stdout) => {
    res.json({ result: stdout || error?.message });
  });
}
