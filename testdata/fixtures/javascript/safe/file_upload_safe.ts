import { Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs';

// SAFE: Multer configured with file size limits and file type filtering
const upload = multer({
  dest: 'uploads/tmp/',
  limits: {
    fileSize: 5 * 1024 * 1024, // SAFE: 5MB file size limit
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    // SAFE: Allowlist of permitted MIME types
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'));
    }
  },
});

export const uploadMiddleware = upload.single('avatar');

export function handleUpload(req: Request, res: Response): void {
  if (!req.file) {
    res.status(400).json({ error: 'No file uploaded' });
    return;
  }

  // SAFE: Validate file extension against allowlist
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];
  const ext = path.extname(req.file.originalname).toLowerCase();

  if (!allowedExtensions.includes(ext)) {
    fs.unlinkSync(req.file.path);
    res.status(400).json({ error: 'File extension not allowed' });
    return;
  }

  // SAFE: Generate random filename to prevent path traversal and overwrite
  const safeFilename = crypto.randomBytes(16).toString('hex') + ext;
  const destPath = path.join('uploads', safeFilename);

  // SAFE: Move file to final destination with safe name
  fs.renameSync(req.file.path, destPath);

  res.json({
    status: 'uploaded',
    filename: safeFilename,
  });
}
