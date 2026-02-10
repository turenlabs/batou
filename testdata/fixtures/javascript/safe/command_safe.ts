import { Request, Response } from 'express';
import { execFile } from 'child_process';
import { spawn } from 'child_process';

// SAFE: Using execFile with separate arguments (no shell injection)
export function pingHost(req: Request, res: Response): void {
  const host = req.query.host as string;

  // Validate hostname format (alphanumeric and dots only)
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    res.status(400).json({ error: 'Invalid hostname format' });
    return;
  }

  // SAFE: execFile passes arguments as an array, not through a shell
  execFile('ping', ['-c', '3', host], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: 'Ping failed' });
      return;
    }
    res.json({ output: stdout });
  });
}

// SAFE: Using spawn with explicit arguments array
export function gitClone(req: Request, res: Response): void {
  const repoUrl = req.body.url;

  // Validate URL format
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\.git$/.test(repoUrl)) {
    res.status(400).json({ error: 'Invalid repository URL' });
    return;
  }

  // SAFE: spawn with array of arguments, no shell interpretation
  const child = spawn('git', ['clone', '--depth', '1', repoUrl, '/tmp/repos/latest'], {
    shell: false,
  });

  let output = '';
  child.stdout.on('data', (data) => { output += data; });
  child.on('close', (code) => {
    res.json({ status: code === 0 ? 'cloned' : 'failed', output });
  });
}
