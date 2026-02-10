import { Request, Response } from 'express';
import * as fs from 'fs';
import * as path from 'path';

// Null byte path truncation vulnerability
// An attacker can request: /file?name=../../../etc/passwd%00.png
// The .png extension check passes, but the null byte truncates the OS path

export function serveImage(req: Request, res: Response): void {
  const imageName = req.query.name as string;

  // Extension check can be bypassed with null byte: "../../etc/passwd\0.png"
  if (!imageName.endsWith('.png') && !imageName.endsWith('.jpg')) {
    res.status(400).send('Only image files allowed');
    return;
  }

  // VULNERABLE: No null byte sanitization before file operation
  const imagePath = path.join('/var/www/images', imageName);

  // VULNERABLE: readFile with user-controlled path, no null byte check
  fs.readFile(imagePath, (err, data) => {
    if (err) {
      res.status(404).send('Image not found');
      return;
    }
    res.type('image/png').send(data);
  });
}

export function downloadAttachment(req: Request, res: Response): void {
  const fileName = req.params.name;

  // VULNERABLE: sendFile with user input, no null byte filtering
  res.sendFile(fileName, { root: './attachments' });
}
