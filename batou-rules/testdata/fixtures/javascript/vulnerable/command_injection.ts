import { Request, Response } from 'express';
import { exec, execSync } from 'child_process';

// VULNERABLE: Command injection via child_process.exec with user input
export function pingHost(req: Request, res: Response): void {
  const host = req.query.host as string;

  // VULNERABLE: exec with string concatenation of user input
  exec('ping -c 3 ' + host, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr });
      return;
    }
    res.json({ output: stdout });
  });
}

// VULNERABLE: Command injection via template literal
export function gitClone(req: Request, res: Response): void {
  const repoUrl = req.body.url;

  // VULNERABLE: execSync with template literal interpolation
  const output = execSync(`git clone ${repoUrl} /tmp/repos/latest`);
  res.json({ status: 'cloned', output: output.toString() });
}

// VULNERABLE: require("child_process").exec usage
export function checkVersion(req: Request, res: Response): void {
  const pkg = req.params.package;
  require("child_process").exec('npm show ' + pkg + ' version', (err: Error | null, out: string) => {
    res.json({ version: out?.trim() });
  });
}
