import { execFile, spawn } from 'child_process';
import { Request, Response } from 'express';

// SAFE: execFile with array arguments (no shell interpolation)
export function resizeImage(req: Request, res: Response): void {
  const width = parseInt(req.query.width as string, 10);
  const height = parseInt(req.query.height as string, 10);

  if (isNaN(width) || isNaN(height) || width < 1 || height < 1 || width > 4096 || height > 4096) {
    res.status(400).json({ error: 'Invalid dimensions' });
    return;
  }

  execFile('convert', [
    'input.png',
    '-resize', String(width) + 'x' + String(height),
    'output.png',
  ], (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: 'Resize failed' });
      return;
    }
    res.json({ success: true });
  });
}

// SAFE: spawn with explicit argument array (no shell)
export function runLinter(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const allowedExtensions = ['.ts', '.js', '.tsx', '.jsx'];
    const ext = filePath.slice(filePath.lastIndexOf('.'));

    if (!allowedExtensions.includes(ext)) {
      reject(new Error('Unsupported file type'));
      return;
    }

    const child = spawn('eslint', ['--format', 'json', filePath], {
      timeout: 30000,
    });

    let output = '';
    child.stdout.on('data', (data: Buffer) => {
      output += data.toString();
    });

    child.on('close', () => {
      resolve(output);
    });
  });
}

// SAFE: Hardcoded command with no user input
export function getSystemInfo(): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('uname', ['-a'], (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(stdout.trim());
    });
  });
}

// SAFE: Validated enum input, not arbitrary user string
export function gitOperation(action: string): Promise<void> {
  const allowedActions = ['status', 'log', 'diff'];
  if (!allowedActions.includes(action)) {
    return Promise.reject(new Error('Unknown action'));
  }

  return new Promise((resolve, reject) => {
    execFile('git', [action], (error) => {
      if (error) { reject(error); return; }
      resolve();
    });
  });
}
