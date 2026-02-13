import * as fs from 'fs';
import * as path from 'path';
import * as yauzl from 'yauzl';

function extractZipSafe(zipPath: string, destDir: string) {
  yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
    zipfile.readEntry();
    zipfile.on('entry', (entry) => {
      const destPath = path.resolve(destDir, entry.fileName);
      // SAFE: validate resolved path starts with destination directory
      if (!destPath.startsWith(path.resolve(destDir) + path.sep)) {
        throw new Error(`Zip slip detected: ${entry.fileName}`);
      }
      const writeStream = fs.createWriteStream(destPath);
      zipfile.openReadStream(entry, (err, readStream) => {
        readStream.pipe(writeStream);
      });
      zipfile.readEntry();
    });
  });
}
